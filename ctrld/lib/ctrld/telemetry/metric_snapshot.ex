defmodule Ctrld.Telemetry.MetricSnapshot do
  @moduledoc """
  One Custom Block's data, taken apart into the rows `metric_samples` holds.

  The appliance writes its whole metric surface into the log recording about
  once a second as a PEN-tagged Custom Block, and those bytes reach this server
  verbatim inside the ring it ships. This module is the reader: it tells a
  reading from the padding block that shares its type and enterprise number,
  refuses one it cannot map, and turns the rest into one row per slot.

  ## Padding is the common case and is not a failure

  The recorder fills the slack behind every sector, and the tail of every sealed
  segment, with a Custom Block whose data is zeroes — or with nothing at all,
  the smallest such block carrying no data. Those arrive here far more often
  than readings do, so `:padding` is an ordinary answer and a caller steps over
  it without counting a fault.

  ## Why a foreign catalogue yields nothing

  A slot means whatever the catalogue at that position means. An appliance built
  against a different catalogue is not partially readable: its slot 300 may be
  another series entirely, and a row written under the wrong name is a
  measurement nothing downstream can question. So a fingerprint that is not this
  build's refuses the whole snapshot.

  ## `Float64` cannot hold every counter, so some samples are refused

  `metric_samples.value` is a `Float64`, whose integers are exact only to
  2^53. A counter above that would be stored rounded — a number that reads as a
  measurement and is not one — so it is **refused by name** instead, and the
  refusal is counted and logged. Nothing this appliance counts reaches 2^53 in
  any plausible life (a nanosecond counter would take about a century), so in
  practice this is the answer to a domain that is faulty or hostile rather than
  to one that is busy, which is exactly when a silently rounded number would be
  worst.
  """

  alias Ctrld.Telemetry.MetricCatalogue

  # The first byte of a Custom Block's data. Zero — or no data at all — is the
  # padding the recorder writes; every other value names a kind, and 1 is a
  # metric reading. Restated here rather than shared with the appliance: the two
  # are separate builds in separate languages, and a constant that could be
  # renamed on one side without failing on the other is not a contract.
  @kind_snapshot 1

  # Bytes ahead of the first slot: kind, version, two reserved, fingerprint,
  # instant, slot count.
  @header_bytes 20

  # The body layout this build reads.
  @version 1

  # The largest integer a `Float64` holds exactly. A counter above it has no
  # honest representation in the column, so it is refused rather than rounded.
  @float64_exact_max 9_007_199_254_740_992

  @typedoc """
  Why a block yielded no samples.

  `:padding` is not a fault — it is the block the recorder fills a sector with.
  Every other member is a block this build will not map, each naming its own
  cause so an operator reading the ingest counters knows which.
  """
  @type refusal ::
          :padding
          | {:unknown_kind, non_neg_integer()}
          | {:unknown_version, non_neg_integer()}
          | :reserved_set
          | {:too_short, non_neg_integer()}
          | {:foreign_catalogue, non_neg_integer(), non_neg_integer()}
          | {:slot_count_mismatch, non_neg_integer(), non_neg_integer()}
          | {:truncated, non_neg_integer(), non_neg_integer()}

  @typedoc """
  What one block was worth: the rows it yielded, and how many slots carried a
  value no column could hold exactly.
  """
  @type reading :: %{rows: [map()], unrepresentable: non_neg_integer()}

  @doc """
  Turn one Custom Block's data into `metric_samples` rows for `device_id`.

  Total over arbitrary bytes: every input is a reading or a named refusal.
  """
  @spec rows(String.t(), binary()) :: {:ok, reading()} | {:error, refusal()}
  def rows(device_id, data) when is_binary(device_id) and is_binary(data) do
    with {:ok, instant, slots} <- decode(data) do
      {:ok, build(device_id, instant, slots)}
    end
  end

  @doc "The PEN-tagged block kind a metric reading carries."
  @spec kind() :: non_neg_integer()
  def kind, do: @kind_snapshot

  @doc "A refusal in the words an operator reading it needs."
  @spec describe(refusal()) :: String.t()
  def describe(:padding), do: "a padding block, which carries no reading"

  def describe({:unknown_kind, kind}),
    do: "a custom block of kind #{kind}, which is not a reading"

  def describe({:unknown_version, version}),
    do: "a reading in body version #{version}, which this server does not read"

  def describe(:reserved_set), do: "a reading whose reserved bytes are not zero"

  def describe({:too_short, len}),
    do: "#{len} bytes, which is fewer than a reading's #{@header_bytes}-byte header"

  def describe({:foreign_catalogue, stated, held}),
    do:
      "a reading against catalogue #{stated}; this server maps catalogue #{held}, so none of " <>
        "its slots can be named"

  def describe({:slot_count_mismatch, stated, held}),
    do: "a reading of #{stated} slots; this server's catalogue has #{held}"

  def describe({:truncated, len, needed}),
    do: "a reading of #{len} bytes where its own header names #{needed}"

  @doc "The tag a counter carries for a refusal, for the ingest telemetry."
  @spec tag(refusal()) :: atom()
  def tag(refusal) when is_atom(refusal), do: refusal
  def tag(refusal) when is_tuple(refusal), do: elem(refusal, 0)

  # The header is matched whole rather than field by field, so a block shorter
  # than one cannot be read past: the clause simply does not match, and the
  # clauses below answer with what arrived.
  @spec decode(binary()) :: {:ok, non_neg_integer(), [non_neg_integer()]} | {:error, refusal()}
  defp decode(<<>>), do: {:error, :padding}
  defp decode(<<0, _rest::binary>>), do: {:error, :padding}

  defp decode(
         <<@kind_snapshot, @version, 0, 0, fingerprint::little-32, instant::little-64,
           stated::little-32, body::binary>>
       ) do
    held = MetricCatalogue.fingerprint()

    cond do
      fingerprint != held ->
        {:error, {:foreign_catalogue, fingerprint, held}}

      stated != MetricCatalogue.slots() ->
        {:error, {:slot_count_mismatch, stated, MetricCatalogue.slots()}}

      byte_size(body) < stated * 8 ->
        {:error, {:truncated, @header_bytes + byte_size(body), @header_bytes + stated * 8}}

      true ->
        {:ok, instant, slots(body, stated)}
    end
  end

  defp decode(<<@kind_snapshot, version, _rest::binary>>) when version != @version,
    do: {:error, {:unknown_version, version}}

  defp decode(<<@kind_snapshot, @version, reserved::binary-size(2), _rest::binary>>)
       when reserved != <<0, 0>>,
       do: {:error, :reserved_set}

  defp decode(<<kind, _rest::binary>>) when kind != @kind_snapshot,
    do: {:error, {:unknown_kind, kind}}

  # A leading byte that names a reading, in bytes that do not reach a header.
  defp decode(data), do: {:error, {:too_short, byte_size(data)}}

  # Exactly the slots the header named, and never a byte past them: the tail of a
  # Custom Block is whatever the writer padded it to, and a reader that took it
  # for values would report padding as measurements.
  #
  # `binary_part/3` cannot raise here: the clause above answers `:truncated`
  # unless `byte_size(body) >= count * 8`, so the span asked for is inside the
  # binary by the time this is reached.
  @spec slots(binary(), non_neg_integer()) :: [non_neg_integer()]
  defp slots(body, count) do
    values = binary_part(body, 0, count * 8)
    for <<value::little-64 <- values>>, do: value
  end

  @spec build(String.t(), non_neg_integer(), [non_neg_integer()]) :: reading()
  defp build(device_id, instant, slots) do
    observed_at = observed_at(instant)

    {rows, unrepresentable} =
      slots
      |> Enum.zip(MetricCatalogue.series())
      |> Enum.reduce({[], 0}, fn {value, {family, labels}}, {rows, refused} ->
        if value > @float64_exact_max do
          {rows, refused + 1}
        else
          row = %{
            device_id: device_id,
            observed_at: observed_at,
            family: family,
            labels: labels,
            value: value
          }

          {[row | rows], refused}
        end
      end)

    %{rows: Enum.reverse(rows), unrepresentable: unrepresentable}
  end

  # The appliance stamps a reading with the instant it was taken at, or zero
  # where it had no clock. Zero is carried through as the epoch rather than
  # replaced with this server's own clock: a row stamped here would claim the
  # appliance knew a time it did not, and the epoch is legible as exactly what it
  # is. Nanoseconds are truncated to the microseconds the column holds.
  #
  # Rendered as a naive date and time with its microseconds always six digits,
  # for the reason `Ctrld.Telemetry.FlowEvent` renders one the same way: the
  # column is `DateTime64(6, 'UTC')` and its `JSONEachRow` reader takes that text
  # and refuses an offset, and a value written to fewer digits would be read as a
  # coarser scale multiplied up — a wrong instant rather than a rejected one.
  #
  # `from_unix!/2` cannot raise on this input: the instant is an unsigned 64-bit
  # count of nanoseconds, so the largest value it can carry is under 2^64 / 10^9
  # seconds past the epoch — the year 2554 — which is inside the range the
  # calendar admits. Every bit pattern a byzantine writer can put in that field
  # names a civil time.
  @spec observed_at(non_neg_integer()) :: String.t()
  defp observed_at(nanos) do
    instant = DateTime.from_unix!(div(nanos, 1_000), :microsecond)

    %{instant | microsecond: {elem(instant.microsecond, 0), 6}}
    |> DateTime.to_naive()
    |> NaiveDateTime.to_string()
  end
end
