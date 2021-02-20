package api_schema

import (
	"net"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/spec_summary"
)

// NetworkDirection is always relative to subject service.
type NetworkDirection string

const (
	Inbound  NetworkDirection = "INBOUND"
	Outbound NetworkDirection = "OUTBOUND"
)

type APISpecState string

const (
	APISpecInitialized APISpecState = "INITIALIZED"
	APISpecComputing   APISpecState = "COMPUTING"
	APISpecDone        APISpecState = "DONE"
	APISpecError       APISpecState = "ERROR"
)

// References an API spec by ID or version. Only one field may be set.
type APISpecReference struct {
	ID      *akid.APISpecID `json:"id,omitempty"`
	Version *string         `json:"version,omitempty"`
}

// Also used as a model in specs_db.
type APISpecVersion struct {
	tableName struct{} `pg:"api_spec_versions" json:"-"`

	Name         string         `pg:"name" json:"name"`
	APISpecID    akid.APISpecID `pg:"api_spec_id" json:"api_spec_id"`
	ServiceID    akid.ServiceID `pg:"service_id" json:"service_id"`
	CreationTime time.Time      `pg:"creation_time" json:"creation_time"`
}

type CheckpointRequest struct {
	// Optional: name to assign to the API spec generated by the checkpoint.
	APISpecName string `json:"api_spec_name"`
}

type CheckpointResponse struct {
	APISpecID akid.APISpecID `json:"api_spec_id"`
}

type CreateLearnSessionRequest struct {
	// Optional argument that specifies an existing API spec that specs generated
	// from this learn session should extend upon.
	BaseAPISpecRef *APISpecReference `json:"base_api_spec_ref,omitempty"`

	// Optional key-value pairs to tag this learn session.
	// We reserve tags with "x-akita" prefix for internal use.
	Tags map[string]string `json:"tags,omitempty"`

	// Optional name for the learn session.
	Name string `json:"name"`
}

// Also used as a model in specs_db.
type LearnSession struct {
	tableName struct{} `pg:"learn_sessions"`

	ID           akid.LearnSessionID `pg:"id,pk" json:"id"`
	Name         string              `pg:"name" json:"name"`
	IdentityID   akid.IdentityID     `pg:"identity_id" json:"identity_id"`
	ServiceID    akid.ServiceID      `pg:"service_id" json:"service_id"`
	CreationTime time.Time           `pg:"creation_time" json:"creation_time"`

	// Optional field whose presence indicates that the learn session is an
	// extension to an existing API spec.
	BaseAPISpecID *akid.APISpecID `pg:"base_api_spec_id" json:"base_api_spec_id,omitempty"`

	// HasMany relationship.
	Tags []LearnSessionTag `json:"tags"`
}

type LearnSessionTag struct {
	tableName struct{} `pg:"learn_session_tags"`

	LearnSessionID akid.LearnSessionID `pg:"learn_session_id" json:"learn_session_id"`
	Key            string              `pg:"key" json:"key"`
	Value          string              `pg:"value,use_zero" json:"value"`
}

type CreateSpecRequest struct {
	// Learn sessions to create spec from.
	LearnSessionIDs []akid.LearnSessionID `json:"learn_session_ids"`

	// Optional: name to assign to the API spec generated by the checkpoint.
	Name string `json:"name"`

	// Optional: user-specified tags.
	Tags map[string]string `json:"tags"`
}

type ListSessionsResponse struct {
	Sessions []*LearnSession `json:"sessions"`
}

type UploadWitnessesRequest struct {
	ClientID akid.ClientID    `json:"client_id"`
	Reports  []*WitnessReport `json:"reports"`
}

type WitnessReport struct {
	Direction       NetworkDirection `json:"direction"`
	OriginAddr      net.IP           `json:"origin_addr"`
	OriginPort      uint16           `json:"origin_port"`
	DestinationAddr net.IP           `json:"destination_addr"`
	DestinationPort uint16           `json:"destination_port"`

	ClientWitnessTime time.Time `json:"client_witness_time"`

	// A serialized Witness protobuf in base64 URL encoded format.
	WitnessProto string `json:"witness_proto"`

	ID   akid.WitnessID    `json:"id"`
	Tags map[string]string `json:"tags"`

	// Hash of the witness proto. Only used internally in the client.
	Hash string `json:"-"`
}

type CreateSpecResponse struct {
	ID akid.APISpecID `json:"id"`
}

type GetSpecMetadataResponse struct {
	// TODO: remove
	// If the spec was created from a learn session, the session's ID is included.
	LearnSessionID *akid.LearnSessionID `json:"learn_session_id,omitempty"`

	// If the spec was created from a learn session, the session's ID is included.
	// If the spec was created by merging other API specs, those spec's session
	// IDs are included.
	LearnSessionIDs []akid.LearnSessionID `json:"learn_session_ids,omitempty"`

	Name string `json:"name"`

	State APISpecState `json:"state"`

	Tags map[string]string `json:"tags"`
}

type GetSpecResponse struct {
	Content string `json:"content"`

	// TODO: remove
	// If the spec was created from a learn session, the session's ID is included.
	LearnSessionID *akid.LearnSessionID `json:"learn_session_id,omitempty"`

	// If the spec was created from a learn session, the session's ID is included.
	// If the spec was created by merging other API specs, those spec's session
	// IDs are included.
	LearnSessionIDs []akid.LearnSessionID `json:"learn_session_ids,omitempty"`

	Name string `json:"name"`

	State APISpecState `json:"state"`

	Summary *spec_summary.Summary `json:"summary,omitempty"`

	Tags map[string]string `json:"tags"`
}