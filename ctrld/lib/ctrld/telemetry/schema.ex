defmodule Ctrld.Telemetry.Schema do
  @moduledoc """
  The ClickHouse schema the appliance's telemetry lands in.

  Three tables, because the appliance produces three kinds of thing and they
  have different shapes: what it decided about a packet, what a protection
  domain said about itself, and what its counters read. All three are
  append-only, queried across wide time ranges and grouped by appliance, which
  is the shape a relational store is wrong for and this one is right for.

  Every column here is a field the appliance already produces — the annotation
  a recording carries on each observation, the log record a domain publishes,
  the metric sample a shard holds — so the schema is the real one and not a
  sketch to be replaced when the channel arrives. What the channel adds is a
  producer; nothing here changes to accept it.

  Partitioning is by month and the sort key leads with the appliance, because
  every question an operator asks starts by naming one appliance and a window.
  """

  @flow_events """
  CREATE TABLE IF NOT EXISTS flow_events (
    device_id           FixedString(32),
    observed_at         DateTime64(6, 'UTC'),
    generation          UInt32,
    interface_id        UInt8,
    direction           Enum8('inbound' = 0, 'outbound' = 1),
    verdict             Enum8('forwarded' = 0, 'dropped' = 1, 'revoked' = 2),
    drop_reason         UInt8,
    flow_class          Enum8('none' = 0, 'new' = 1, 'established' = 2, 'related' = 3),
    event               Enum8('none' = 0, 'flow-opened' = 1, 'flow-advanced' = 2,
                              'flow-closed' = 3, 'policy-denied' = 4, 'policy-no-match' = 5,
                              'flow-refused' = 6, 'flow-revoked' = 7),
    flow_state          UInt8,
    flow_slot           UInt32,
    flow_occupant       UInt32,
    matched_rule        UInt16,
    protocol            UInt8,
    source_address      IPv4,
    destination_address IPv4,
    source_port         UInt16,
    destination_port    UInt16,
    ingested_at         DateTime64(6, 'UTC') DEFAULT now64(6)
  )
  ENGINE = MergeTree
  PARTITION BY toYYYYMM(observed_at)
  ORDER BY (device_id, observed_at, flow_slot, flow_occupant)
  """

  @log_events """
  CREATE TABLE IF NOT EXISTS log_events (
    device_id   FixedString(32),
    observed_at DateTime64(6, 'UTC'),
    domain      LowCardinality(String),
    severity    LowCardinality(String),
    event       LowCardinality(String),
    detail      String,
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6)
  )
  ENGINE = MergeTree
  PARTITION BY toYYYYMM(observed_at)
  ORDER BY (device_id, observed_at, domain)
  """

  @metric_samples """
  CREATE TABLE IF NOT EXISTS metric_samples (
    device_id   FixedString(32),
    observed_at DateTime64(6, 'UTC'),
    family      LowCardinality(String),
    labels      Map(LowCardinality(String), String),
    value       Float64,
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6)
  )
  ENGINE = MergeTree
  PARTITION BY toYYYYMM(observed_at)
  ORDER BY (device_id, family, observed_at)
  """

  @doc "The tables this schema owns."
  @spec tables() :: [String.t()]
  def tables, do: ~w(flow_events log_events metric_samples)

  @doc """
  The statements that bring the schema up, in order.

  They are all `IF NOT EXISTS`, so running them is how the schema is applied
  and re-applying them is a no-operation rather than an error — which is what
  lets the gate and a development start both call it unconditionally.
  """
  @spec statements() :: [String.t()]
  def statements, do: [@flow_events, @log_events, @metric_samples]
end
