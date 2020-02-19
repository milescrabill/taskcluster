const assert = require('assert');
const slugid = require('slugid');
const _ = require('lodash');
const taskcluster = require('taskcluster-client');
const forge = require('node-forge');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const generator = require('generate-password');

const auth = require('@azure/ms-rest-nodeauth');
const ComputeManagementClient = require('@azure/arm-compute').ComputeManagementClient;
const NetworkManagementClient = require('@azure/arm-network').NetworkManagementClient;
const msRestJS = require('@azure/ms-rest-js');
const msRestAzure = require('@azure/ms-rest-azure-js');

const {ApiError, Provider} = require('./provider');
const {CloudAPI} = require('./cloudapi');

// only use alphanumeric characters for convenience
function nicerId() {
  return (slugid.nice() + slugid.nice() + slugid.nice()).toLowerCase().replace(/[^A-Za-z0-9]/g, '');
}

// The password must be between 8-72 characters long (Linux max is 72)
// must satisfy >= 3 of password complexity requirements from the following:
//   1) Contains an uppercase character
//   2) Contains a lowercase character
//   3) Contains a numeric digit
//   4) Contains a special character
//   5) Control characters are not allowed
function generateAdminPassword() {
  // using `strict: true` ensures we match requirements
  return generator.generate({
    length: 72,
    lowercase: true,
    uppercase: true,
    numbers: true,
    symbols: true,
    strict: true,
  });
}

class AzureProvider extends Provider {

  constructor({
    providerConfig,
    fakeCloudApis,
    ...conf
  }) {
    super(conf);
    this.configSchema = 'config-azure';
    this.providerConfig = providerConfig;
    this.fakeCloudApis = fakeCloudApis;
  }

  async setup() {
    let {
      clientId,
      secret,
      domain,
      subscriptionId,
      apiRateLimits = {},
      _backoffDelay = 1000,
    } = this.providerConfig;

    // Azure SDK has builtin retry logic: https://docs.microsoft.com/en-us/azure/architecture/best-practices/retry-service-specific
    // compute rate limiting: https://docs.microsoft.com/en-us/azure/virtual-machines/troubleshooting/troubleshooting-throttling-errors
    const cloud = new CloudAPI({
      types: ['query', 'get', 'list', 'opRead'],
      apiRateLimits,
      intervalDefault: 100 * 1000, // Intervals are enforced every 100 seconds
      intervalCapDefault: 2000, // The calls we make are all limited 20/sec so 20 * 100 are allowed
      monitor: this.monitor,
      providerId: this.providerId,
      errorHandler: ({err, tries}) => {
        if (err.code === 429) { // too many requests
          return {backoff: _backoffDelay * 50, reason: 'rateLimit', level: 'notice'};
        } else if (err.code >= 500) { // For 500s, let's take a shorter backoff
          return {backoff: _backoffDelay * Math.pow(2, tries), reason: 'errors', level: 'warning'};
        }
        // If we don't want to do anything special here, just throw and let the
        // calling code figure out what to do
        throw err;
      },
    });
    this._enqueue = cloud.enqueue.bind(cloud);

    // load microsoft intermediate certs from disk
    // TODO (bug 1607922) : we should download the intermediate certs,
    //       locations are in the authorityInfoAccess extension
    let intermediateFiles = [1, 2, 4, 5].map(i => fs.readFileSync(path.resolve(__dirname, `azure-ca-certs/microsoft_it_tls_ca_${i}.pem`)));
    let intermediateCerts = intermediateFiles.map(forge.pki.certificateFromPem);
    this.caStore = forge.pki.createCaStore(intermediateCerts);

    if (this.fakeCloudApis && this.fakeCloudApis.azure) {
      this.computeClient = this.fakeCloudApis.azure.compute();
      this.networkClient = this.fakeCloudApis.azure.network();
      return;
    }

    let credentials = await auth.loginWithServicePrincipalSecret(clientId, secret, domain);
    this.computeClient = new ComputeManagementClient(credentials, subscriptionId);
    this.networkClient = new NetworkManagementClient(credentials, subscriptionId);
    this.restClient = new msRestAzure.AzureServiceClient(credentials);
  }

  async provision({workerPool, existingCapacity}) {
    const {workerPoolId} = workerPool;
    let toSpawn = await this.estimator.simple({
      workerPoolId,
      ...workerPool.config,
      existingCapacity,
    });

    if (toSpawn === 0) {
      return; // Nothing to do
    }

    let registrationExpiry = null;
    if ((workerPool.config.lifecycle || {}).registrationTimeout) {
      registrationExpiry = Date.now() + workerPool.config.lifecycle.registrationTimeout * 1000;
    }

    const cfgs = [];
    while (toSpawn > 0) {
      const cfg = _.sample(workerPool.config.launchConfigs);
      cfgs.push(cfg);
      toSpawn -= cfg.capacityPerInstance;
    }

    // Create "empty" workers to provision in _provisionResources loop
    await Promise.all(cfgs.map(async cfg => {
      // This must be unique to currently existing instances and match [a-z]([-a-z0-9]*[a-z0-9])?
      // The lost entropy from downcasing, etc should be ok due to the fact that
      // only running instances need not be identical. We do not use this name to identify
      // workers in taskcluster.
      const poolName = workerPoolId.replace(/[\/_]/g, '-').slice(0, 38);
      const virtualMachineName = `vm-${poolName}-${nicerId()}`.slice(0, 38);
      // Windows computer name cannot be more than 15 characters long, be entirely numeric,
      // or contain the following characters: ` ~ ! @ # $ % ^ & * ( ) = + _ [ ] { } \\ | ; : . " , < > / ?
      const computerName = nicerId().slice(0, 15);
      const ipAddressName = `pip-${nicerId()}`.slice(0, 24);
      const networkInterfaceName = `nic-${nicerId()}`.slice(0, 24);
      const diskName = `disk-${nicerId()}`.slice(0, 24);

      const customData = Buffer.from(JSON.stringify({
        workerPoolId,
        providerId: this.providerId,
        workerGroup: this.providerId,
        rootUrl: this.rootUrl,
        workerConfig: cfg.workerConfig || {},
      })).toString('base64');

      const config = {
        ...cfg,
        osProfile: {
          ...cfg.osProfile,
          // Windows admin user name cannot be more than 20 characters long, be empty,
          // end with a period(.), or contain the following characters: \\ / \" [ ] : | < > + = ; , ? * @.
          adminUsername: nicerId().slice(0, 20),
          // we have to set a password, but we never want it to be used, so we throw it away
          // a legitimate user who needs access can reset the password
          adminPassword: generateAdminPassword(),
          computerName,
          customData,
        },
        storageProfile: {
          ...cfg.storageProfile,
          osDisk: {
            ...(cfg.storageProfile || {}).osDisk,
            name: diskName,
          },
        },
        networkProfile: {
          ...cfg.networkProfile,
          // we add this when we have the NIC provisioned
          networkInterfaces: [],
        },
        tags: {
          ...cfg.tags || {},
          'created-by': `taskcluster-wm-${this.providerId}`.replace(/[^a-zA-Z0-9-]/g, '-'),
          'managed-by': 'taskcluster',
          'worker-pool-id': workerPoolId.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase(),
          'owner': workerPool.owner.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase(),
        },
      };

      let providerData = {
        location: cfg.location,
        resourceGroupName: this.providerConfig.resourceGroupName,
        vm: {
          name: virtualMachineName,
          computerName,
          config,
          operation: false,
          id: false,
        },
        ip: {
          name: ipAddressName,
          operation: false,
          id: false,
        },
        nic: {
          name: networkInterfaceName,
          operation: false,
          id: false,
        },
        disk: {
          // created by the VM operation
          name: diskName,
          id: false,
        },
        subnet: {
          id: cfg.subnetId,
        },
      };

      this.monitor.log.workerRequested({
        workerPoolId,
        providerId: this.providerId,
        workerGroup: this.providerId,
        workerId: virtualMachineName,
      });
      const now = new Date();
      await this.Worker.create({
        workerPoolId,
        providerId: this.providerId,
        workerGroup: this.providerId,
        workerId: virtualMachineName,
        created: now,
        lastModified: now,
        lastChecked: now,
        expires: taskcluster.fromNow('1 week'),
        state: this.Worker.states.REQUESTED,
        capacity: cfg.capacityPerInstance,
        providerData: {
          ...providerData,
          registrationExpiry,
        },
      });
    }));
  }

  async deprovision({workerPool}) {
    // nothing to do: we just wait for workers to terminate themselves
  }

  _now() {
    return new Date();
  }

  async registerWorker({worker, workerPool, workerIdentityProof}) {
    const {document} = workerIdentityProof;

    // use the same message for all errors here, so as not to give an attacker
    // extra information.
    const error = () => new ApiError('Signature validation error');

    // workerIdentityProof is a signed message

    // We need to check that:
    // 1. The embedded document was signed with the private key corresponding to the
    //    embedded public key
    // 2. The embedded public key has a proper certificate chain back to a trusted CA
    // 3. The embedded message contains the vmId that matches the worker making the request

    // signature is base64-encoded DER-format PKCS#7 / CMS message

    // decode base64, load DER, extract PKCS#7 message
    let decodedMessage = Buffer.from(document, 'base64');
    let message;
    try {
      let asn1 = forge.asn1.fromDer(forge.util.createBuffer(decodedMessage));
      message = forge.pkcs7.messageFromAsn1(asn1);
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Error extracting PKCS#7 message', error: err.toString()});
      throw error();
    }

    let content, crt, pem, sig;
    // get message content, signing certificate, and signature
    try {
      // in testing, message.content is empty, so we access the raw ASN1 structure
      content = message.rawCapture.content.value[0].value;
      // convert to pem for convenience
      assert.equal(message.certificates.length, 1, `Expected one certificate in message, received ${message.certificates.length}`);
      crt = message.certificates[0];
      pem = forge.pki.publicKeyToPem(crt.publicKey);
      sig = message.rawCapture.signature;
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Error extracting PKCS#7 message content', error: err.toString()});
      throw error();
    }

    // verify that the message is properly signed
    try {
      let verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(Buffer.from(content));
      assert(verifier.verify(pem, sig, 'binary'));
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Error verifying PKCS#7 message signature', error: err.toString()});
      throw error();
    }

    // verify that the embedded certificates have proper chain of trust
    try {
      forge.pki.verifyCertificateChain(this.caStore, [crt]);
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Error verifying certificate chain', error: err.message});
      throw error();
    }

    let payload;
    try {
      payload = JSON.parse(content);
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Payload was not valid JSON', error: err.toString()});
      throw error();
    }

    // verify that the embedded vmId matches what the worker is sending
    try {
      assert.equal(payload.vmId, worker.workerId);
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Encountered vmId mismatch', error: err.toString(), vmId: payload.vmId, workerId: worker.workerId});
      throw error();
    }

    // verify that the message is not expired
    try {
      assert(new Date(payload.timeStamp.expiresOn) > this._now());
    } catch (err) {
      this.monitor.log.registrationErrorWarning({message: 'Expired message', error: err.toString(), expires: payload.timeStamp.expiresOn});
      throw error();
    }

    if (worker.state !== this.Worker.states.REQUESTED) {
      this.monitor.log.registrationErrorWarning({message: 'Worker was already running.', error: 'Worker was already running.'});
      throw error();
    }

    this.monitor.log.workerRunning({
      workerPoolId: workerPool.workerPoolId,
      providerId: this.providerId,
      workerId: worker.workerId,
    });
    await worker.modify(w => {
      w.lastModified = new Date();
      w.state = this.Worker.states.RUNNING;
    });

    // assume for the moment that workers self-terminate before 96 hours
    return {expires: taskcluster.fromNow('96 hours')};
  }

  async scanPrepare() {
    this.seen = {};
    this.errors = {};
  }

  /**
   * Used to check in on the state of any operations
   * that are ongoing. This should not be used to gate
   * any other actions in the provider as we may fail to write these
   * operations when we create them. This is just a nice-to-have for
   * reporting configuration/provisioning errors to the users.
   *
   * op: an object with keys `name` and optionally `region` or `zone` if it is a region or zone based operation
   * errors: a list that will have any errors found for that operation appended to it
   */
  async handleOperation({op, errors}) {
    // op is a URL to follow-up on operation progress
    let req, resp;
    req = new msRestJS.WebResource(op, 'GET');
    // sendLongRunningRequest polls until finished but this is just reading
    // the status of an operation so it shouldn't block long
    // it's ok if we hit an error here, that will trigger resource teardown
    resp = await this._enqueue('opRead', () => this.restClient.sendLongRunningRequest(req));
    if (resp.status === 404) {
      // operation not found because it has either expired or does not exist
      // nothing more to do
      return false;
    }

    let body = resp.parsedBody;
    if (body) {
      // status is guaranteed to exist if the operation was found
      if (body.status === 'InProgress') {
        return true;
      }
    }

    return false;
  }

  async _provisionResource(client, {worker}, resourceType, resourceConfig, modifyCallback) {
    if (!_.has(worker.providerData, resourceType)) {
      throw new Error(`Worker providerData does not contain resourceType ${resourceType}`);
    }
    let typeData = worker.providerData[resourceType];
    if (!typeData.id) {
      try {
        let resource = await this._enqueue('query', () => client.get(
          worker.providerData.resourceGroupName,
          typeData.name,
        ));
        await worker.modify(w => {
          w.providerData[resourceType].id = resource.id;
          modifyCallback(w, resource);
        });
      } catch (err) {
        if (err.statusCode !== 404) {
          // we should have an operation, check status
          let opResult;
          if (typeData.operation) {
            opResult = await this.handleOperation({op: typeData.operation, errors: this.errors[worker.workerPoolId]});
          }
          if (!opResult) {
            throw err;
          }
        }
      }
    }
    if (!typeData.id) {
      // we need to create the resource
      let resourceRequest = await this._enqueue('query', () => client.beginCreateOrUpdate(
        worker.providerData.resourceGroupName,
        typeData.name,
        resourceConfig,
      ));
      await worker.modify(w => {
        w.providerData[resourceType].operation = resourceRequest.getPollState().azureAsyncOperationHeaderValue;
      });
    }
  }

  async _provisionResources({worker}) {
    let data = worker.providerData;
    let ipAddressRequest, networkInterfaceRequest, virtualMachineRequest;

    // For each resource:
    // Do we have an ID? If not, do we have a name?
    // // Look up resource by name
    // // // If the resource exists, get its ID, save it, continue
    // // // If the resource does not exist, create it
    // // // If we encounter a non-404 error looking for a resource, check its operation for errors
    // We have an ID => we can use that ID to provision the next resource
    try {
      // check whether the IP exists _now_
      // or check on the operation that is creating it
      if (!data.ip.id) {
        try {
          let ipAddress = await this._enqueue('query', () => this.networkClient.publicIPAddresses.get(
            data.resourceGroupName,
            data.ip.name,
          ));
          await worker.modify(w => {
            w.providerData.ip.id = ipAddress.id;
          });
        } catch (err) {
          if (err.statusCode !== 404) {
            // we have an operation from the create request, check status
            let opResult;
            if (data.ip.operation) {
              opResult = await this.handleOperation({op: data.ip.operation, errors: this.errors[worker.workerPoolId]});
            }
            if (!opResult) {
              throw err;
            }
          }
        }
      }

      // if we got an IP from above, we'll skip this
      // otherwise, we'll request a new IP
      if (!data.ip.id) {
        // we need to create a fresh IP
        ipAddressRequest = await this._enqueue('query', () => this.networkClient.publicIPAddresses.beginCreateOrUpdate(
          data.resourceGroupName,
          data.ip.name,
          {
            location: data.location,
            publicIPAllocationMethod: 'Dynamic',
          },
        ));
        await worker.modify(w => {
          w.providerData.ip.operation = ipAddressRequest.getPollState().azureAsyncOperationHeaderValue;
        });
        // this resource is not yet ready
        // we have to wait for the next iteration
        return;
      }

      if (!data.nic.id) {
        try {
          let networkInterface = await this._enqueue('query', () => this.networkClient.networkInterfaces.get(
            data.resourceGroupName,
            data.nic.name,
          ));
          await worker.modify(w => {
            w.providerData.nic.id = networkInterface.id;
            // we needed NIC id to create this
            w.providerData.vm.config.networkProfile.networkInterfaces = [
              {
                id: data.nic.id,
                primary: true,
              },
            ];
          });
        } catch (err) {
          if (err.statusCode !== 404) {
            // we should have an operation, check status
            let opResult;
            if (data.nic.operation) {
              opResult = await this.handleOperation({op: data.nic.operation, errors: this.errors[worker.workerPoolId]});
            }
            if (!opResult) {
              throw err;
            }
          }
        }
      }

      if (!data.nic.id) {
        // we need to create a fresh NIC
        networkInterfaceRequest = await this._enqueue('query', () => this.networkClient.networkInterfaces.beginCreateOrUpdate(
          data.resourceGroupName,
          data.nic.name,
          {
            location: data.location,
            ipConfigurations: [
              {
                name: data.nic.name,
                privateIPAllocationMethod: 'Dynamic',
                subnet: {
                  id: data.subnet.id,
                },
                publicIPAddress: {
                  id: data.ip.id,
                },
              },
            ],
          },
        ));
        await worker.modify(w => {
          w.providerData.nic.operation = networkInterfaceRequest.getPollState().azureAsyncOperationHeaderValue;
        });
        // this resource is not yet ready
        // we have to wait for the next iteration
        return;
      }

      // check whether the VM exists _now_
      // or check on the operation that is creating it
      if (!data.vm.id) {
        try {
          let vm = await this._enqueue('query', () => this.computeClient.virtualMachines.get(
            data.resourceGroupName,
            data.vm.name,
          ));
          await worker.modify(w => {
            w.providerData.vm.id = vm.id;
          });
        } catch (err) {
          if (err.statusCode !== 404) {
            // we should have an operation, check status
            let opResult;
            if (data.vm.operation) {
              opResult = await this.handleOperation({op: data.vm.operation, errors: this.errors[worker.workerPoolId]});
            }
            if (!opResult) {
              throw err;
            }
          }
        }
      }

      // if we got an IP from above, we'll skip this
      // otherwise, we'll request a new IP
      if (!data.vm.id) {
        // we need to create a fresh IP
        virtualMachineRequest = await this._enqueue('query', () => this.computeClient.virtualMachines.beginCreateOrUpdate(
          data.resourceGroupName,
          data.vm.name,
          data.vm.config,
        ));
        await worker.modify(w => {
          w.providerData.vm.operation = virtualMachineRequest.getPollState().azureAsyncOperationHeaderValue;
        });
        // this resource is not yet ready
        // we have to wait for the next iteration
        return;
      }
    } catch (err) {
      // we create multiple resources in order to provision a VM
      // if we catch an error we want to deprovision those resources
      await this._removeWorker({...data});
      await worker.workerPool.reportError({
        kind: 'creation-error',
        title: 'VM Creation Error',
        description: err.message,
        extra: err.details,
      });
      return;
    }
  }

  async checkWorker({worker}) {
    const states = this.Worker.states;
    this.seen[worker.workerPoolId] = this.seen[worker.workerPoolId] || 0;
    this.errors[worker.workerPoolId] = this.errors[worker.workerPoolId] || [];
    console.log(`${worker.workerId}`);

    if (worker.providerData.registrationExpiry &&
      worker.state === states.REQUESTED &&
      worker.providerData.registrationExpiry < Date.now()) {
      return await this.removeWorker({worker});
    }

    let state = worker.state;
    try {
      const {provisioningState} = await this._enqueue('get', () => this.computeClient.virtualMachines.get(
        worker.providerData.resourceGroupName,
        worker.providerData.vm.name,
      ));
      console.log(`${worker.workerId}, ${state}, ${provisioningState}`);
      if (['Creating', 'Updating', 'Starting', 'Running', 'Succeeded'].includes(provisioningState)) {
        this.seen[worker.workerPoolId] += worker.capacity || 1;

        // If the worker will be expired soon but it still exists,
        // update it to stick around a while longer. If this doesn't happen,
        // long-lived instances become orphaned from the provider. We don't update
        // this on every loop just to avoid the extra work when not needed
        if (worker.expires < taskcluster.fromNow('1 day')) {
          await worker.modify(w => {
            w.expires = taskcluster.fromNow('1 week');
          });
        }
      } else if (['Failed', 'Canceled', 'Deleting', 'Deallocating', 'Stopped', 'Deallocated'].includes(provisioningState)) {
        await this.removeWorker({worker});
        this.monitor.log.workerStopped({
          workerPoolId: worker.workerPoolId,
          providerId: this.providerId,
          workerId: worker.workerId,
        });
        state = states.STOPPED;
      } else {
        await worker.workerPool.reportError({
          kind: 'creation-error',
          title: 'Encountered unknown VM provisioningState',
          description: `Unknown provisioningState ${provisioningState}`,
        });
      }
    } catch (err) {
      if (err.code !== 'ResourceNotFound') {
        throw err;
      }
      await this._provisionResources({worker});
      // TODO: we need a new cleanup approach
      // await this.removeWorker({worker});
      // this.monitor.log.workerStopped({
      //   workerPoolId: worker.workerPoolId,
      //   providerId: this.providerId,
      //   workerId: worker.workerId,
      // });
      // state = states.STOPPED;
    }
    await worker.modify(w => {
      const now = new Date();
      if (w.state !== state) {
        w.lastModified = now;
      }
      w.lastChecked = now;
      w.state = state;
    });
  }

  /*
   * Called after an iteration of the worker scanner
   */
  async scanCleanup() {
    this.monitor.log.scanSeen({providerId: this.providerId, seen: this.seen});
    await Promise.all(Object.entries(this.seen).map(async ([workerPoolId, seen]) => {
      const workerPool = await this.WorkerPool.load({
        workerPoolId,
      }, true);

      if (!workerPool) {
        return; // In this case, the workertype has been deleted so we can just move on
      }

      if (this.errors[workerPoolId].length) {
        await Promise.all(this.errors[workerPoolId].map(error => workerPool.reportError(error)));
      }
    }));
  }

  async _removeWorker({resourceGroupName, location, vm, ip, nic, disk}) {
    // clean up related resources, continue on errors
    // delete VM, IP, NIC, and disk
    const ignoreNotFound = async (promise) => {
      try {
        await promise;
      } catch (err) {
        if (err.code === 404) {
          return; // Nothing to do, it is already gone
        }
        throw err;
      }
    };
    // VM, disk, and NIC _should_ be able to be deleted in parallel
    // if we get "in use" failures for NIC/disk they will be retried
    await Promise.all([
      ignoreNotFound(this._enqueue('query', () => this.computeClient.virtualMachines.deleteMethod(
        resourceGroupName,
        vm.name,
      ))),
      ignoreNotFound(this._enqueue('query', () => this.networkClient.networkInterfaces.deleteMethod(
        resourceGroupName,
        nic.name,
      ))),
      await ignoreNotFound(this._enqueue('query', () => this.computeClient.disks.deleteMethod(
        resourceGroupName,
        disk.name,
      ))),
    ]);
    // the public IP cannot be deleted as long as it is attached
    // can become orphaned if we try to delete before the NIC is deleted
    await ignoreNotFound(this._enqueue('query', () => this.networkClient.publicIPAddresses.deleteMethod(
      resourceGroupName,
      ip.name,
    )));
  }

  async removeWorker({worker}) {
    await this._removeWorker({...worker.providerData});
  }
}

module.exports = {
  AzureProvider,
};
