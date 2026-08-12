defmodule Ctrld.Telemetry.LogRecord do
  @moduledoc """
  One Custom Block's data, taken apart into the rows `log_events` holds.

  The appliance's console domain renders every log record its eleven peers
  publish, puts the line on the serial port, and publishes the same bytes to the
  domain that writes the recording medium. Those lines arrive here verbatim
  inside the ring the appliance ships, batched into PEN-tagged Custom Blocks.
  This module is the reader: it tells a batch from the padding block and the
  metric reading that share its type and enterprise number, refuses what it
  cannot read, and turns the rest into one row per line.

  ## What is stored is the line the operator read

  A row's `detail` is the console line itself, byte for byte as the appliance
  printed it. That is the whole design and not a shortcut. The grammar that turns
  a structured record into a line is a large closed vocabulary of the
  appliance's — dozens of detail shapes over eighteen enumerations — and a server
  that re-rendered records would be a second copy of that grammar in another
  language, drifting from the first with no failing test behind it. Storing the
  line means what an operator reads on the console and what a query returns are
  the same text by construction, and the appliance's own boot gate holds the two
  surfaces to each other.

  So `detail` is not a leftover field: it is the record. The three columns beside
  it are what a query needs to *find* a line without parsing it.

  ## `domain` is the ring, not the record's own claim

  A writing domain owns its log ring and may put any `domain=` token it likes in
  a record it publishes; which ring a record came out of is decided by the
  appliance's capability topology and no writing domain can forge it. So the
  origin the console carries beside each line is the unforgeable half, and that
  is what lands in `domain`. The record's own claim is still visible — it is in
  the line, where an operator reading the console sees it too.

  The vocabulary those origins index into is generated from the appliance's own
  `lfw_log::Domain` into `priv/log_domains.json`, for the reason the metric
  catalogue is generated: two hand-kept copies of one table in two languages is a
  drift with no failing test behind it.

  ## `severity` holds a lifecycle point and not a syslog level

  Said plainly, because the column name invites the other reading: for a
  protection-domain record `severity` holds the record's *state* — one of
  `starting`, `negotiated`, `ready` and `refused` — which is where a domain is in
  its own lifecycle, not how bad the news is. A `refused` record is the one that
  reports a failure; `ready` is a domain announcing that it works. For a
  configuration record there is no state at all and the column is empty.

  The column is arguably misnamed for what the appliance produces, and this
  server does not rename a schema column to suit itself. What it does is refuse
  to pretend: nothing here maps a lifecycle point onto `warn` or `error`, because
  no such judgement exists on the appliance and inventing one would put a
  severity in the store that no domain ever claimed.

  ## `event` is the record's shape

  Four values, from the line's own leading tag and the fields it carries:
  `domain` for a protection-domain lifecycle record, and `config-change`,
  `config-generation` and `config-rejected` for the three configuration shapes.
  It is read out of the line's grammar rather than carried as a byte, because the
  tag is the first token of every line and a shape that could disagree with the
  text beside it would be a fifth thing to keep in step.
  """

  # The first byte of a Custom Block's data. Zero — or no data at all — is the
  # padding the recorder writes, 1 is a metric reading and 2 is a batch of
  # console transcript lines. Restated here rather than shared with the
  # appliance, for the reason `Ctrld.Telemetry.MetricSnapshot` restates its own:
  # the two are separate builds in separate languages, and a constant that could
  # be renamed on one side without failing on the other is not a contract.
  @kind_transcript 2

  # Bytes ahead of the first entry: kind, version, two reserved, entry count, two
  # more reserved.
  @header_bytes 8

  # The body layout this build reads.
  @version 1

  # The one flag bit an entry may set: its instant is a real one rather than the
  # absence of one. Any other bit is a writer this build does not share a layout
  # with.
  @flag_stamped 1

  # The longest line the appliance's console grammar renders.
  @max_line_bytes 256

  @external_resource Path.join(:code.priv_dir(:ctrld), "log_domains.json")

  # In discriminant order, so an origin byte is an index. A tuple rather than a
  # list because that index is what every row does.
  @domains @external_resource
           |> File.read!()
           |> Jason.decode!()
           |> Map.fetch!("domains")
           |> List.to_tuple()

  if tuple_size(@domains) == 0 do
    raise "priv/log_domains.json declares no protection domain, so no origin could be named"
  end

  @typedoc """
  Why a block yielded no rows.

  `:padding` and `:metric_reading` are not faults — they are the two other things
  a Custom Block of this enterprise number carries, and a caller steps over both.
  Every other member is a block this build will not read, each naming its own
  cause so an operator reading the ingest counters knows which.
  """
  @type refusal ::
          :padding
          | :metric_reading
          | {:unknown_kind, non_neg_integer()}
          | {:unknown_version, non_neg_integer()}
          | :reserved_set
          | {:too_short, non_neg_integer()}
          | {:truncated, non_neg_integer()}
          | {:unknown_flags, non_neg_integer(), non_neg_integer()}
          | {:unprintable, non_neg_integer()}
          | {:unknown_origin, non_neg_integer()}

  @typedoc """
  What one block was worth: the rows it yielded, and how many entries were
  refused after the ones before them had been read.
  """
  @type batch :: %{rows: [map()], refused: non_neg_integer()}

  @doc """
  Turn one Custom Block's data into `log_events` rows for `device_id`.

  Total over arbitrary bytes: every input is a batch or a named refusal, and a
  malformed entry ends the walk with the rows before it standing — what was whole
  was printed, and discarding it would lose transcript to punish its neighbour.
  """
  @spec rows(String.t(), binary()) :: {:ok, batch()} | {:error, refusal()}
  def rows(device_id, data) when is_binary(device_id) and is_binary(data) do
    with {:ok, entries} <- decode(data) do
      {:ok, build(device_id, entries)}
    end
  end

  @doc "The PEN-tagged block kind a console transcript batch carries."
  @spec kind() :: non_neg_integer()
  def kind, do: @kind_transcript

  @doc "The protection domains an origin byte names, in discriminant order."
  @spec domains() :: [String.t()]
  def domains, do: Tuple.to_list(@domains)

  @doc "A refusal in the words an operator reading it needs."
  @spec describe(refusal()) :: String.t()
  def describe(:padding), do: "a padding block, which carries no transcript"

  def describe(:metric_reading), do: "a metric reading, which is not a transcript"

  def describe({:unknown_kind, kind}),
    do: "a custom block of kind #{kind}, which is not a transcript"

  def describe({:unknown_version, version}),
    do: "a transcript in body version #{version}, which this server does not read"

  def describe(:reserved_set), do: "a transcript whose reserved bytes are not zero"

  def describe({:too_short, len}),
    do: "#{len} bytes, which is fewer than a transcript's #{@header_bytes}-byte header"

  def describe({:truncated, at}),
    do: "a transcript whose line #{at + 1} runs past the bytes that carry it"

  def describe({:unknown_flags, at, flags}),
    do:
      "a transcript whose line #{at + 1} carries flags #{flags}, which this server does not read"

  def describe({:unprintable, at}),
    do:
      "a transcript whose line #{at + 1} carries a byte no console line can, so it is not a line " <>
        "this appliance printed"

  def describe({:unknown_origin, origin}),
    do: "a transcript line from ring #{origin}; this server knows #{tuple_size(@domains)} domains"

  @doc "The tag a counter carries for a refusal, for the ingest telemetry."
  @spec tag(refusal()) :: atom()
  def tag(refusal) when is_atom(refusal), do: refusal
  def tag(refusal) when is_tuple(refusal), do: elem(refusal, 0)

  # The header is matched whole rather than field by field, so a block shorter
  # than one cannot be read past: the clause simply does not match, and the
  # clauses below answer with what arrived.
  @spec decode(binary()) ::
          {:ok, [{non_neg_integer(), nil | non_neg_integer(), binary()}]} | {:error, refusal()}
  defp decode(<<>>), do: {:error, :padding}
  defp decode(<<0, _rest::binary>>), do: {:error, :padding}
  defp decode(<<1, _rest::binary>>), do: {:error, :metric_reading}

  # The stated count bounds the walk from above and the bytes that remain bound it
  # from below, and the second is the one that makes it total: every entry consumes
  # at least its own twelve-byte header, so a count no correct writer produced runs
  # out of bytes and is refused as truncated rather than looping.
  defp decode(<<@kind_transcript, @version, 0, 0, stated::little-16, 0, 0, body::binary>>),
    do: entries(body, stated, 0, [])

  defp decode(<<@kind_transcript, version, _rest::binary>>) when version != @version,
    do: {:error, {:unknown_version, version}}

  defp decode(<<@kind_transcript, @version, reserved::binary-size(2), _rest::binary>>)
       when reserved != <<0, 0>>,
       do: {:error, :reserved_set}

  defp decode(
         <<@kind_transcript, @version, 0, 0, _count::binary-size(2), reserved::binary-size(2),
           _rest::binary>>
       )
       when reserved != <<0, 0>>,
       do: {:error, :reserved_set}

  defp decode(<<kind, _rest::binary>>) when kind != @kind_transcript,
    do: {:error, {:unknown_kind, kind}}

  # A leading byte that names a transcript, in bytes that do not reach a header.
  defp decode(data), do: {:error, {:too_short, byte_size(data)}}

  # Exactly the entries the header named, walked one at a time and bounded twice:
  # by the stated count, itself bounded above by the relay's own slot count, and
  # by the bytes that remain. The tail of a Custom Block is whatever the writer
  # padded it to, and a reader that walked to the end of the data would take that
  # padding for another entry.
  @spec entries(binary(), non_neg_integer(), non_neg_integer(), list()) ::
          {:ok, list()} | {:error, refusal()}
  defp entries(_body, 0, _at, taken), do: {:ok, Enum.reverse(taken)}

  defp entries(
         <<origin, flags, len::little-16, instant::little-64, rest::binary>>,
         left,
         at,
         taken
       )
       when len <= @max_line_bytes and byte_size(rest) >= len do
    cond do
      Bitwise.band(flags, Bitwise.bnot(@flag_stamped)) != 0 ->
        {:error, {:unknown_flags, at, flags}}

      true ->
        <<line::binary-size(^len), tail::binary>> = rest

        if printable?(line) do
          stamp = if Bitwise.band(flags, @flag_stamped) == 0, do: nil, else: instant
          entries(tail, left - 1, at + 1, [{origin, stamp, line} | taken])
        else
          {:error, {:unprintable, at}}
        end
    end
  end

  # An entry whose header does not fit, or whose stated length runs past the bytes
  # behind it, or which claims a line longer than the relay can carry. The rows
  # before it stand; the caller counts the refusal.
  defp entries(_body, _left, at, _taken), do: {:error, {:truncated, at}}

  # The alphabet the appliance's console grammar renders and nothing else. A slot
  # the console never reached is zeroes and a slot read while it was being written
  # is two lines spliced, so this is what keeps text no domain ever printed out of
  # the store — embedded NULs included, which the column could not hold anyway.
  @spec printable?(binary()) :: boolean()
  defp printable?(line), do: for(<<byte <- line>>, byte < 0x20 or byte > 0x7E, do: byte) == []

  @spec build(String.t(), list()) :: batch()
  defp build(device_id, entries) do
    {rows, refused} =
      Enum.reduce(entries, {[], 0}, fn {origin, instant, line}, {rows, refused} ->
        case domain(origin) do
          nil ->
            {rows, refused + 1}

          name ->
            row = %{
              device_id: device_id,
              observed_at: observed_at(instant),
              domain: name,
              severity: severity(line),
              event: event(line),
              detail: line
            }

            {[row | rows], refused}
        end
      end)

    %{rows: Enum.reverse(rows), refused: refused}
  end

  @spec domain(non_neg_integer()) :: nil | String.t()
  defp domain(origin) when origin < tuple_size(@domains), do: elem(@domains, origin)
  defp domain(_origin), do: nil

  # The record's shape, from the line's leading tag and the field that follows the
  # instant. A closed set of four, matching the appliance's four record shapes.
  @spec event(binary()) :: String.t()
  defp event("LFW-PD " <> _rest), do: "domain"

  defp event("LFW-CFG " <> rest) do
    cond do
      String.contains?(rest, " change=") -> "config-change"
      String.contains?(rest, " rejected=") -> "config-rejected"
      String.contains?(rest, " outcome=") -> "config-generation"
      true -> "config"
    end
  end

  defp event(_line), do: "unknown"

  # The `state=` token of a protection-domain record, which is a lifecycle point
  # and not a level — see this module's own note on the column. Empty for a
  # configuration record, which carries no state.
  @spec severity(binary()) :: String.t()
  defp severity(line) do
    case Regex.run(~r/ state=([a-z-]+)/, line, capture: :all_but_first) do
      [state] -> state
      nil -> ""
    end
  end

  # The appliance stamps a line with the instant the record was emitted at, or
  # with nothing where the domain that emitted it had no clock — which most of a
  # boot transcript does not. `nil` is stored as the epoch rather than replaced
  # with this server's own clock, for the reason
  # `Ctrld.Telemetry.MetricSnapshot` carries a zero through: a row stamped here
  # would claim the appliance knew a time it did not, and the epoch is legible as
  # exactly what it is. The line itself still says `time=unsynchronized`.
  #
  # Rendered as a naive date and time with its microseconds always six digits, for
  # `Ctrld.Telemetry.FlowEvent`'s reason: the column is `DateTime64(6, 'UTC')` and
  # its `JSONEachRow` reader takes that text and refuses an offset, so a value
  # written to fewer digits would be read as a coarser scale multiplied up.
  #
  # `from_unix!/2` cannot raise on this input: the instant is an unsigned 64-bit
  # count of nanoseconds, so the largest it can carry is the year 2554, which is
  # inside the range the calendar admits.
  @spec observed_at(nil | non_neg_integer()) :: String.t()
  defp observed_at(nil), do: observed_at(0)

  defp observed_at(nanos) do
    instant = DateTime.from_unix!(div(nanos, 1_000), :microsecond)

    %{instant | microsecond: {elem(instant.microsecond, 0), 6}}
    |> DateTime.to_naive()
    |> NaiveDateTime.to_string()
  end
end
