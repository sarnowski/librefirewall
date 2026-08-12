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
  sketch to be replaced when the channel arrives.

  Partitioning is by month and the sort key leads with the appliance, because
  every question an operator asks starts by naming one appliance and a window.

  ## `log_events.severity` holds a lifecycle point, not a level

  Stated here because the column name invites the other reading. The appliance
  makes no severity judgement anywhere: a protection-domain record carries the
  domain's *state* — `starting`, `negotiated`, `ready` or `refused` — and that is
  what this column stores, with `refused` being the one that reports a failure and
  `ready` a domain announcing that it works. A configuration record carries no
  state at all and the column is empty for one.

  So the column is arguably misnamed for what this appliance produces. It is not
  renamed here, and nothing maps a lifecycle point onto `warn` or `error` either:
  a severity in the store that no domain ever claimed would be worse than a column
  whose name is a little wide. `Ctrld.Telemetry.LogRecord` is the producer and
  says the same thing.

  ## An enumeration is declared once

  The four enumerated columns of `flow_events` are built from the tables below
  rather than written out in the statement, and those same tables are what a
  producer holds an annotation's code against before it batches a row. That is
  not tidiness either: ClickHouse refuses a whole `JSONEachRow` batch over one
  value outside a declared enumeration, so a producer that guessed which codes
  are declared would lose the rows around the one it guessed wrong about. One
  declaration read by both makes the guess unrepresentable.
  """

  # The appliance's own vocabularies, by the code each member arrives as. A code
  # is the wire value the annotation carries and the value stored, so the name
  # beside it is a label for a reader and never something a producer resolves
  # through.
  @direction %{0 => "inbound", 1 => "outbound"}
  @verdict %{0 => "forwarded", 1 => "dropped", 2 => "revoked"}
  @flow_class %{0 => "none", 1 => "new", 2 => "established", 3 => "related"}
  @event %{
    0 => "none",
    1 => "flow-opened",
    2 => "flow-advanced",
    3 => "flow-closed",
    4 => "policy-denied",
    5 => "policy-no-match",
    6 => "flow-refused",
    7 => "flow-revoked"
  }

  @flow_event_enums %{
    direction: @direction,
    verdict: @verdict,
    flow_class: @flow_class,
    event: @event
  }

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
  The enumerated columns of `flow_events`, each as its codes and their names.

  This is the declaration a producer checks a code against, and the one the
  statement below is built from.
  """
  @spec flow_event_enums() :: %{atom() => %{non_neg_integer() => String.t()}}
  def flow_event_enums, do: @flow_event_enums

  @doc """
  Whether `column` declares `code`.

  Answers false for a column that is not enumerated at all, so a caller cannot
  get a pass out of a misspelt name.
  """
  @spec declares?(atom(), term()) :: boolean()
  def declares?(column, code) do
    case Map.fetch(@flow_event_enums, column) do
      {:ok, members} -> Map.has_key?(members, code)
      :error -> false
    end
  end

  @doc """
  The statements that bring the schema up, in order.

  They are all `IF NOT EXISTS`, so running them is how the schema is applied
  and re-applying them is a no-operation rather than an error — which is what
  lets the gate and a development start both call it unconditionally.
  """
  @spec statements() :: [String.t()]
  def statements, do: [flow_events(), @log_events, @metric_samples]

  @spec flow_events() :: String.t()
  defp flow_events do
    """
    CREATE TABLE IF NOT EXISTS flow_events (
      device_id           FixedString(32),
      observed_at         DateTime64(6, 'UTC'),
      generation          UInt32,
      interface_id        UInt8,
      direction           #{enum8(@direction)},
      verdict             #{enum8(@verdict)},
      drop_reason         UInt8,
      flow_class          #{enum8(@flow_class)},
      event               #{enum8(@event)},
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
  end

  @spec enum8(%{non_neg_integer() => String.t()}) :: String.t()
  defp enum8(members) do
    body =
      members
      |> Enum.sort()
      |> Enum.map_join(", ", fn {code, name} -> "'#{name}' = #{code}" end)

    "Enum8(#{body})"
  end
end
