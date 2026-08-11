defmodule Ctrld.Telemetry.FiveTuplePropertyTest do
  @moduledoc """
  What has to hold for every byte string there is: the reader answers, and its
  answer is a five-tuple or a refusal with a name.

  These bytes are the most hostile this server handles. They are not the
  appliance's — they are whatever some host on a customer's network put on a
  wire, copied verbatim into a recording and shipped here — so the property is
  not that arbitrary input parses, which almost none of it does, but that
  arbitrary input is *answered*: no raise, no exit, no reason tuple whose tag
  this build has no words for. A refusal nobody named is one nobody can act on,
  and a raise here would take a whole appliance's ingest down over one frame.

  The generator is seeded, so a failure is one anybody can reproduce from the
  seed printed beside it. Its cases are the ones that find different faults:
  bytes with no structure at all, prefixes of frames the appliance really
  recorded, and those frames with single bytes flipped — the last being what
  gets past the EtherType and deep into a header before it goes wrong.
  """

  use ExUnit.Case, async: true

  alias Ctrld.{Pcapng, RecordingFixtures}
  alias Ctrld.Pcapng.Packet
  alias Ctrld.Telemetry.FiveTuple

  # Every reason this build knows how to state. A tag outside this set means the
  # reader invented a refusal nobody has written words for.
  @tags MapSet.new([
          :no_frame,
          :shorter_than_ethernet,
          :not_ipv4_ethertype,
          :shorter_than_ipv4,
          :not_ipv4,
          :header_below_minimum,
          :header_exceeds_frame,
          :later_fragment,
          :shorter_than_ports
        ])

  @seed 20_260_811
  @mutations 2_000

  test "arbitrary bytes are always answered, never raised on" do
    for {label, bytes} <- cases() do
      answered(label, bytes)
    end
  end

  test "a refusal never carries a byte the peer chose" do
    # A refusal is rendered onto an operator's log, which is not one of the two
    # artifacts allowed to carry traffic. So what a refusal may hold is a length,
    # a version, a protocol number and an EtherType — never a run of the frame.
    for {label, bytes} <- cases() do
      case FiveTuple.read(bytes) do
        {:ok, %FiveTuple{}} ->
          :ok

        {:error, reason} when is_atom(reason) ->
          :ok

        {:error, reason} ->
          refute Enum.any?(Tuple.to_list(reason), &is_binary/1),
                 "#{label}: refusal #{inspect(reason)} carries bytes from the frame"
      end
    end
  end

  test "reading is bounded by the bytes in hand" do
    # A frame is read in a fixed number of steps with no loop in it, so a large
    # one costs no more than a small one beyond the match itself. What this
    # holds is the consequence: a frame at the appliance's own snap length and
    # one a thousand times larger are both answered, and neither runs away.
    for size <- [64, 1_500, 65_535, Pcapng.max_block_bytes()] do
      frame = frame_of(size)
      answered("#{size}-byte frame", frame)
    end
  end

  defp answered(label, bytes) do
    case FiveTuple.read(bytes) do
      {:ok, %FiveTuple{} = tuple} ->
        assert tuple.protocol in 0..255, "#{label}: protocol out of range"
        assert tuple.source_port in 0..65_535, "#{label}: source port out of range"
        assert tuple.destination_port in 0..65_535, "#{label}: destination port out of range"

      {:error, reason} ->
        tag = if is_atom(reason), do: reason, else: elem(reason, 0)

        assert MapSet.member?(@tags, tag),
               "#{label}: refused under #{inspect(tag)}, which this build has no words for"

        assert is_binary(FiveTuple.describe(reason)),
               "#{label}: #{inspect(tag)} does not describe"
    end
  end

  defp cases do
    noise() ++ truncations() ++ mutations()
  end

  defp noise do
    generator = :rand.seed_s(:exsss, {@seed, 1, 1})

    {cases, _generator} =
      Enum.map_reduce(0..200, generator, fn index, generator ->
        {size, generator} = :rand.uniform_s(80, generator)
        {bytes, generator} = random_bytes(size - 1, generator, <<>>)
        {{"noise #{index}", bytes}, generator}
      end)

    cases
  end

  defp truncations do
    for frame <- frames(), size <- 0..min(byte_size(frame), 48) do
      {"prefix of #{size}", binary_part(frame, 0, size)}
    end
  end

  defp mutations do
    frames = frames()
    generator = :rand.seed_s(:exsss, {@seed, 2, 2})

    {cases, _generator} =
      Enum.map_reduce(1..@mutations, generator, fn index, generator ->
        {which, generator} = :rand.uniform_s(length(frames), generator)
        frame = Enum.at(frames, which - 1)
        {at, generator} = :rand.uniform_s(byte_size(frame), generator)
        {value, generator} = :rand.uniform_s(256, generator)

        mutated =
          binary_part(frame, 0, at - 1) <>
            <<value - 1>> <> binary_part(frame, at, byte_size(frame) - at)

        {{"mutation #{index}", mutated}, generator}
      end)

    cases
  end

  # The frames the appliance really recorded, which is where a mutation has
  # something worth breaking.
  defp frames do
    RecordingFixtures.names()
    |> Enum.flat_map(fn name ->
      {:ok, blocks, _decoder} = Pcapng.decode(Pcapng.new(), RecordingFixtures.read!(name))
      for %Packet{data: data} <- blocks, data != <<>>, do: data
    end)
    |> Enum.uniq()
  end

  defp frame_of(size) do
    header = <<0::12*8, 0x0800::unsigned-big-16, 0x45, 0::18*8>>
    header <> :binary.copy(<<0xAB>>, max(size - byte_size(header), 0))
  end

  defp random_bytes(0, generator, acc), do: {acc, generator}

  defp random_bytes(remaining, generator, acc) do
    {value, generator} = :rand.uniform_s(256, generator)
    random_bytes(remaining - 1, generator, acc <> <<value - 1>>)
  end
end
