defmodule Ctrld.Telemetry.FlowEvent do
  @moduledoc """
  One decoded record, as the row `flow_events` holds.

  The row is made of three things that arrive separately and are joined here:
  the record's own instant, the annotation the appliance wrote beside it, and
  the five-tuple read out of the recorded frame. Nothing else is needed and
  nothing else is invented — every column below is a value one of those three
  already carries.

  Two column names differ from the field they come from, and deliberately:
  `flow_occupant` is the annotation's `flow_generation`, which is the count of
  how many conversations a slot has held rather than a configuration
  generation and reads as the latter beside `generation`; and `flow_class` is
  its `classification`, which says what the flow was to the tracker.

  ## The enumerated columns carry numbers

  The four `Enum8` columns are written as the appliance's own codes rather than
  as the names the schema declares beside them, because those codes are what
  the annotation carries and ClickHouse takes either through `JSONEachRow`.
  Writing the number is the shorter path and the safer one: a name would be
  this build's rendering of a vocabulary that lives in another language, and a
  rendering that drifted would be written as a *different member* rather than
  refused, which is the one failure a stored enumeration cannot recover from.

  ## A record without a row

  Two shapes have no row at all, and both are counted rather than dropped
  quietly. A record whose annotation this build could not read carries no
  verdict, no flow and no event, so a row built from it would be five real
  columns and eleven zeroes that look like decisions the appliance made. And a
  record whose annotation carries a code outside what the schema declares
  cannot be written at all: ClickHouse refuses the whole batch over one such
  value, so a producer that sent it would lose every row beside it.

  Where the *frame* could not be read the record still has a row — the
  annotation is the evidence and it is intact — and the five-tuple columns
  carry what a frame nothing could read is worth, which
  `Ctrld.Telemetry.FiveTuple.absent/0` defines and the refusal beside the row
  names.
  """

  alias Ctrld.Pcapng.{Annotation, Packet}
  alias Ctrld.Telemetry.{FiveTuple, Schema}

  @typedoc """
  Why a record has no row.

  `:annotation_unrecognised` is a layout version this build does not read;
  `{:undeclared_code, column, code}` is a vocabulary that has grown past the
  schema, and names which one so the schema can be extended rather than
  guessed at.
  """
  @type refusal :: :annotation_unrecognised | {:undeclared_code, atom(), non_neg_integer()}

  @typedoc """
  What one record is worth.

  A row comes with the frame refusal that shaped its five-tuple columns, or
  `nil` where the frame was read — so a caller counts what it inserted and what
  it could not read about, without inspecting the row it just built.
  """
  @type outcome :: {:row, map(), nil | FiveTuple.refusal()} | {:no_row, refusal()}

  @doc "Turn one decoded record into the row it is, or say why it is none."
  @spec row(String.t(), Packet.t()) :: outcome()
  def row(device_id, %Packet{annotation: nil}) when is_binary(device_id),
    do: {:no_row, :annotation_unrecognised}

  def row(device_id, %Packet{annotation: %Annotation{} = annotation} = packet)
      when is_binary(device_id) do
    case undeclared(annotation) do
      nil -> built(device_id, packet, annotation)
      refusal -> {:no_row, refusal}
    end
  end

  @doc "A refusal in the words an operator reading it needs."
  @spec describe(refusal()) :: String.t()
  def describe(:annotation_unrecognised),
    do: "a record carries an annotation layout this build does not read"

  def describe({:undeclared_code, column, code}),
    do: "a record states #{column} #{code}, which the telemetry schema does not declare"

  @spec built(String.t(), Packet.t(), Annotation.t()) :: outcome()
  defp built(device_id, %Packet{} = packet, %Annotation{} = annotation) do
    {tuple, frame_refusal} =
      case FiveTuple.read(packet.data) do
        {:ok, tuple} -> {tuple, nil}
        {:error, refusal} -> {FiveTuple.absent(), refusal}
      end

    row = %{
      device_id: device_id,
      observed_at: instant(packet.observed_at),
      generation: annotation.generation,
      # The annotation's own interface rather than the block's: they agree on
      # every record an appliance writes, and where they would not, the one the
      # appliance decided against is the one its verdict means.
      interface_id: annotation.interface_id,
      direction: annotation.direction,
      verdict: annotation.verdict,
      drop_reason: annotation.drop_reason,
      flow_class: annotation.classification,
      event: annotation.event,
      flow_state: annotation.flow_state,
      flow_slot: annotation.flow_slot,
      flow_occupant: annotation.flow_generation,
      matched_rule: annotation.matched_rule,
      protocol: tuple.protocol,
      source_address: dotted(tuple.source_address),
      destination_address: dotted(tuple.destination_address),
      source_port: tuple.source_port,
      destination_port: tuple.destination_port
    }

    {:row, row, frame_refusal}
  end

  # The enumerated columns, held against the one declaration of what they may
  # carry. A code outside it is the appliance's vocabulary having grown, which
  # is a schema change and not something to round off here.
  @spec undeclared(Annotation.t()) :: nil | refusal()
  defp undeclared(%Annotation{} = annotation) do
    [
      {:direction, annotation.direction},
      {:verdict, annotation.verdict},
      {:flow_class, annotation.classification},
      {:event, annotation.event}
    ]
    |> Enum.find_value(fn {column, code} ->
      unless Schema.declares?(column, code), do: {:undeclared_code, column, code}
    end)
  end

  # ClickHouse reads a `DateTime64(6)` from this text form, and the fraction has
  # to be six digits: a value written to fewer would be read as a coarser time
  # scaled up, which is a wrong instant rather than a rejected one.
  @spec instant(DateTime.t()) :: String.t()
  defp instant(%DateTime{} = observed_at) do
    %{observed_at | microsecond: {elem(observed_at.microsecond, 0), 6}}
    |> DateTime.to_naive()
    |> NaiveDateTime.to_string()
  end

  @spec dotted(FiveTuple.address()) :: String.t()
  defp dotted({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
end
