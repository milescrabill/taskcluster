// This source code file is AUTO-GENERATED by github.com/taskcluster/jsonschema2go

package tchooks

import (
	"encoding/json"
	"errors"

	tcclient "github.com/taskcluster/taskcluster-client-go"
)

type (
	// Exchange and RoutingKeyPattern for each binding
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/bindings.json#/properties/items
	Binding struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/bindings.json#/properties/items/properties/exchange
		Exchange string `json:"exchange"`

		// See https://taskcluster-staging.net/schemas/hooks/v1/bindings.json#/properties/items/properties/routingKeyPattern
		RoutingKeyPattern string `json:"routingKeyPattern"`
	}

	// Information about an unsuccessful firing of the hook
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[1]
	FailedFire struct {

		// The error that occurred when firing the task.  This is typically,
		// but not always, an API error message.
		//
		// Additional properties allowed
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[1]/properties/error
		Error json.RawMessage `json:"error"`

		// Possible values:
		//   * "error"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[1]/properties/result
		Result string `json:"result"`

		// The time the task was created.  This will not necessarily match `task.created`.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[1]/properties/time
		Time tcclient.Time `json:"time"`
	}

	// Definition of a hook that can create tasks at defined times.
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#
	HookCreationRequest struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/bindings.json#
		Bindings []interface{} `json:"bindings,omitempty"`

		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 64
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#/properties/hookGroupId
		HookGroupID string `json:"hookGroupId,omitempty"`

		// Syntax:     ^([a-zA-Z0-9-_/]*)$
		// Min length: 1
		// Max length: 64
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#/properties/hookId
		HookID string `json:"hookId,omitempty"`

		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#
		Metadata HookMetadata `json:"metadata"`

		// Definition of the times at which a hook will result in creation of a task.
		// If several patterns are specified, tasks will be created at any time
		// specified by one or more patterns.
		//
		// Default:    []
		//
		// Array items:
		// Cron-like specification for when tasks should be created.  The pattern is
		// parsed in a UTC context.
		// See [cron-parser on npm](https://www.npmjs.com/package/cron-parser).
		// Note that tasks may not be created at exactly the time specified.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#/properties/schedule/items
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#/properties/schedule
		Schedule []string `json:"schedule,omitempty"`

		// Template for the task definition.  This is rendered using [JSON-e](https://taskcluster.github.io/json-e/)
		// as described in [firing hooks](/docs/reference/core/taskcluster-hooks/docs/firing-hooks) to produce
		// a task definition that is submitted to the Queue service.
		//
		// Additional properties allowed
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#/properties/task
		Task json.RawMessage `json:"task"`

		// Default:    {
		//               "additionalProperties": false,
		//               "type": "object"
		//             }
		//
		// Additional properties allowed
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/create-hook-request.json#/properties/triggerSchema
		TriggerSchema json.RawMessage `json:"triggerSchema,omitempty"`
	}

	// Definition of a hook that will create tasks when defined events occur.
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/hook-definition.json#
	HookDefinition struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/bindings.json#
		Bindings []interface{} `json:"bindings,omitempty"`

		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 64
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-definition.json#/properties/hookGroupId
		HookGroupID string `json:"hookGroupId"`

		// Syntax:     ^([a-zA-Z0-9-_/]*)$
		// Min length: 1
		// Max length: 64
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-definition.json#/properties/hookId
		HookID string `json:"hookId"`

		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#
		Metadata HookMetadata `json:"metadata"`

		// Definition of the times at which a hook will result in creation of a task.
		// If several patterns are specified, tasks will be created at any time
		// specified by one or more patterns.  Note that tasks may not be created
		// at exactly the time specified.
		//                     {$ref: "schedule.json#"}
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-definition.json#/properties/schedule
		Schedule json.RawMessage `json:"schedule"`

		// Template for the task definition.  This is rendered using [JSON-e](https://taskcluster.github.io/json-e/)
		// as described in [firing hooks](/docs/reference/core/taskcluster-hooks/docs/firing-hooks) to produce
		// a task definition that is submitted to the Queue service.
		//
		// Additional properties allowed
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-definition.json#/properties/task
		Task json.RawMessage `json:"task"`

		// Additional properties allowed
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-definition.json#/properties/triggerSchema
		TriggerSchema json.RawMessage `json:"triggerSchema"`
	}

	// List of `hookGroupIds`.
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/list-hook-groups-response.json#
	HookGroups struct {

		// Array items:
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-hook-groups-response.json#/properties/groups/items
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-hook-groups-response.json#/properties/groups
		Groups []string `json:"groups"`
	}

	// List of hooks
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/list-hooks-response.json#
	HookList struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/list-hooks-response.json#/properties/hooks
		Hooks []HookDefinition `json:"hooks"`
	}

	// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#
	HookMetadata struct {

		// Long-form of the hook's purpose and behavior
		//
		// Max length: 32768
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#/properties/description
		Description string `json:"description"`

		// Whether to email the owner on an error creating the task.
		//
		// Default:    true
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#/properties/emailOnError
		EmailOnError bool `json:"emailOnError,omitempty"`

		// Human readable name of the hook
		//
		// Max length: 255
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#/properties/name
		Name string `json:"name"`

		// Email of the person or group responsible for this hook.
		//
		// Max length: 255
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-metadata.json#/properties/owner
		Owner string `json:"owner"`
	}

	// A snapshot of the current status of a hook.
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#
	HookStatusResponse struct {

		// Information about the last time this hook fired.  This property is only present
		// if the hook has fired at least once.
		//
		// One of:
		//   * SuccessfulFire
		//   * FailedFire
		//   * NoFire
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire
		LastFire json.RawMessage `json:"lastFire"`

		// The next time this hook's task is scheduled to be created. This property
		// is only present if there is a scheduled next time. Some hooks don't have
		// any schedules.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/nextScheduledDate
		NextScheduledDate tcclient.Time `json:"nextScheduledDate,omitempty"`
	}

	// List of lastFires
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#
	LastFiresList struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires
		LastFires []Var `json:"lastFires"`
	}

	// See https://taskcluster-staging.net/schemas/hooks/v1/bindings.json#
	ListOfBindings []interface{}

	// Information about no firing of the hook (e.g., a new hook)
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[2]
	NoFire struct {

		// Possible values:
		//   * "no-fire"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[2]/properties/result
		Result string `json:"result"`
	}

	// JSON object with information about a run
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items
	RunInformation struct {

		// Reason for the creation of this run,
		// **more reasons may be added in the future**.
		//
		// Possible values:
		//   * "scheduled"
		//   * "retry"
		//   * "task-retry"
		//   * "rerun"
		//   * "exception"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/reasonCreated
		ReasonCreated string `json:"reasonCreated"`

		// Reason that run was resolved, this is mainly
		// useful for runs resolved as `exception`.
		// Note, **more reasons may be added in the future**, also this
		// property is only available after the run is resolved.
		//
		// Possible values:
		//   * "completed"
		//   * "failed"
		//   * "deadline-exceeded"
		//   * "canceled"
		//   * "superseded"
		//   * "claim-expired"
		//   * "worker-shutdown"
		//   * "malformed-payload"
		//   * "resource-unavailable"
		//   * "internal-error"
		//   * "intermittent-task"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/reasonResolved
		ReasonResolved string `json:"reasonResolved,omitempty"`

		// Date-time at which this run was resolved, ie. when the run changed
		// state from `running` to either `completed`, `failed` or `exception`.
		// This property is only present after the run as been resolved.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/resolved
		Resolved tcclient.Time `json:"resolved,omitempty"`

		// Id of this task run, `run-id`s always starts from `0`
		//
		// Mininum:    0
		// Maximum:    1000
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/runId
		RunID int64 `json:"runId"`

		// Date-time at which this run was scheduled, ie. when the run was
		// created in state `pending`.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/scheduled
		Scheduled tcclient.Time `json:"scheduled"`

		// Date-time at which this run was claimed, ie. when the run changed
		// state from `pending` to `running`. This property is only present
		// after the run has been claimed.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/started
		Started tcclient.Time `json:"started,omitempty"`

		// State of this run
		//
		// Possible values:
		//   * "pending"
		//   * "running"
		//   * "completed"
		//   * "failed"
		//   * "exception"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/state
		State string `json:"state"`

		// Time at which the run expires and is resolved as `failed`, if the
		// run isn't reclaimed. Note, only present after the run has been
		// claimed.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/takenUntil
		TakenUntil tcclient.Time `json:"takenUntil,omitempty"`

		// Identifier for group that worker who executes this run is a part of,
		// this identifier is mainly used for efficient routing.
		// Note, this property is only present after the run is claimed.
		//
		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 22
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/workerGroup
		WorkerGroup string `json:"workerGroup,omitempty"`

		// Identifier for worker evaluating this run within given
		// `workerGroup`. Note, this property is only available after the run
		// has been claimed.
		//
		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 22
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs/items/properties/workerId
		WorkerID string `json:"workerId,omitempty"`
	}

	// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status
	Status struct {

		// Deadline of the task, `pending` and `running` runs are
		// resolved as **exception** if not resolved by other means
		// before the deadline. Note, deadline cannot be more than
		// 5 days into the future
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/deadline
		Deadline tcclient.Time `json:"deadline"`

		// Task expiration, time at which task definition and
		// status is deleted. Notice that all artifacts for the task
		// must have an expiration that is no later than this.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/expires
		Expires tcclient.Time `json:"expires"`

		// Unique identifier for the provisioner that this task must be scheduled on
		//
		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 22
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/provisionerId
		ProvisionerID string `json:"provisionerId"`

		// Number of retries left for the task in case of infrastructure issues
		//
		// Mininum:    0
		// Maximum:    999
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/retriesLeft
		RetriesLeft int64 `json:"retriesLeft"`

		// List of runs, ordered so that index `i` has `runId == i`
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/runs
		Runs []RunInformation `json:"runs"`

		// Identifier for the scheduler that _defined_ this task.
		//
		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 22
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/schedulerId
		SchedulerID string `json:"schedulerId"`

		// State of this task. This is just an auxiliary property derived from state
		// of latests run, or `unscheduled` if none.
		//
		// Possible values:
		//   * "unscheduled"
		//   * "pending"
		//   * "running"
		//   * "completed"
		//   * "failed"
		//   * "exception"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/state
		State string `json:"state"`

		// Identifier for a group of tasks scheduled together with this task, by
		// scheduler identified by `schedulerId`. For tasks scheduled by the
		// task-graph scheduler, this is the `taskGraphId`.
		//
		// Syntax:     ^[A-Za-z0-9_-]{8}[Q-T][A-Za-z0-9_-][CGKOSWaeimquy26-][A-Za-z0-9_-]{10}[AQgw]$
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/taskGroupId
		TaskGroupID string `json:"taskGroupId"`

		// Unique task identifier, this is UUID encoded as
		// [URL-safe base64](http://tools.ietf.org/html/rfc4648#section-5) and
		// stripped of `=` padding.
		//
		// Syntax:     ^[A-Za-z0-9_-]{8}[Q-T][A-Za-z0-9_-][CGKOSWaeimquy26-][A-Za-z0-9_-]{10}[AQgw]$
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/taskId
		TaskID string `json:"taskId"`

		// Identifier for worker type within the specified provisioner
		//
		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 22
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status/properties/workerType
		WorkerType string `json:"workerType"`
	}

	// Information about a successful firing of the hook
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[0]
	SuccessfulFire struct {

		// Possible values:
		//   * "success"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[0]/properties/result
		Result string `json:"result"`

		// The task created
		//
		// Syntax:     ^[A-Za-z0-9_-]{8}[Q-T][A-Za-z0-9_-][CGKOSWaeimquy26-][A-Za-z0-9_-]{10}[AQgw]$
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[0]/properties/taskId
		TaskID string `json:"taskId"`

		// The time the task was created.  This will not necessarily match `task.created`.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/hook-status.json#/properties/lastFire/oneOf[0]/properties/time
		Time tcclient.Time `json:"time"`
	}

	// A representation of **task status** as known by the queue
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#
	TaskStatusStructure struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/task-status.json#/properties/status
		Status Status `json:"status"`
	}

	// A request to trigger a hook.  The payload must be a JSON object, and is used as the context
	// for a JSON-e rendering of the hook's task template, as described in "Firing Hooks".
	//
	// Additional properties allowed
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/trigger-hook.json#
	TriggerHookRequest json.RawMessage

	// Secret token for a trigger
	//
	// See https://taskcluster-staging.net/schemas/hooks/v1/trigger-token-response.json#
	TriggerTokenResponse struct {

		// See https://taskcluster-staging.net/schemas/hooks/v1/trigger-token-response.json#/properties/token
		Token string `json:"token"`
	}

	// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items
	Var struct {

		// The error that occurred when firing the task. This is typically,
		// but not always, an API error message.
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/error
		Error string `json:"error"`

		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/firedBy
		FiredBy string `json:"firedBy,omitempty"`

		// Syntax:     ^([a-zA-Z0-9-_]*)$
		// Min length: 1
		// Max length: 64
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/hookGroupId
		HookGroupID string `json:"hookGroupId"`

		// Syntax:     ^([a-zA-Z0-9-_/]*)$
		// Min length: 1
		// Max length: 64
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/hookId
		HookID string `json:"hookId"`

		// Information about success or failure of firing of the hook
		//
		// Possible values:
		//   * "success"
		//   * "error"
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/result
		Result string `json:"result"`

		// Time when the task was created
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/taskCreateTime
		TaskCreateTime tcclient.Time `json:"taskCreateTime"`

		// Unique task identifier, this is UUID encoded as
		// [URL-safe base64](http://tools.ietf.org/html/rfc4648#section-5) and
		// stripped of `=` padding.
		//
		// Syntax:     ^[A-Za-z0-9_-]{8}[Q-T][A-Za-z0-9_-][CGKOSWaeimquy26-][A-Za-z0-9_-]{10}[AQgw]$
		//
		// See https://taskcluster-staging.net/schemas/hooks/v1/list-lastFires-response.json#/properties/lastFires/items/properties/taskId
		TaskID string `json:"taskId"`
	}
)

// MarshalJSON calls json.RawMessage method of the same name. Required since
// TriggerHookRequest is of type json.RawMessage...
func (this *TriggerHookRequest) MarshalJSON() ([]byte, error) {
	x := json.RawMessage(*this)
	return (&x).MarshalJSON()
}

// UnmarshalJSON is a copy of the json.RawMessage implementation.
func (this *TriggerHookRequest) UnmarshalJSON(data []byte) error {
	if this == nil {
		return errors.New("TriggerHookRequest: UnmarshalJSON on nil pointer")
	}
	*this = append((*this)[0:0], data...)
	return nil
}
