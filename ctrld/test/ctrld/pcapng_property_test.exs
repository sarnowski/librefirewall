defmodule Ctrld.PcapngPropertyTest do
  @moduledoc """
  What has to hold for every byte string there is: the decoder answers, and its
  answer is either blocks or a refusal with a name.

  These bytes derive from network traffic and reach this server through an
  appliance that is authenticated but not trusted with this process's liveness.
  So the property is not that arbitrary input decodes — almost none of it does —
  but that arbitrary input is *answered*: no raise, no exit, no unbounded
  allocation, and no reason tuple whose tag this build does not know, since a
  refusal nobody named is a refusal nobody can act on.

  The generator is seeded rather than random, so a failure is a failure anybody
  can reproduce from the seed printed beside it. Its cases are the three that
  find different bugs: bytes with no structure at all, prefixes of real
  recordings, and real recordings with single bytes flipped — the last being the
  one that gets deep into a block before it goes wrong.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Pcapng
  alias Ctrld.RecordingFixtures

  # Every reason this build knows how to state. A tag outside this set means the
  # decoder invented a refusal nobody has written words for.
  @tags MapSet.new([
          :not_a_section_header,
          :bad_byte_order_magic,
          :unsupported_section_version,
          :unknown_block_type,
          :block_too_short,
          :block_too_long,
          :block_length_not_aligned,
          :length_trailer_mismatch,
          :packet_exceeds_block,
          :captured_exceeds_original,
          :payload_padding_not_zero,
          :truncated_option,
          :unterminated_options,
          :trailing_option_bytes,
          :option_padding_not_zero,
          :option_terminator_not_empty,
          :option_length_unexpected,
          :unsupported_timestamp_resolution,
          :unknown_interface,
          :too_many_interfaces,
          :timestamp_out_of_range
        ])

  @seed 20_260_811

  test "arbitrary bytes are always answered, never raised on" do
    for {label, bytes} <- cases() do
      answered(label, bytes)
    end
  end

  test "arbitrary bytes delivered in arbitrary pieces are answered the same way" do
    generator = :rand.seed_s(:exsss, {@seed, 2, 3})

    Enum.reduce(cases(), generator, fn {label, bytes}, generator ->
      {pieces, generator} = cut(bytes, generator)

      # Cutting the input cannot turn an answer into a crash, whatever the input
      # was: what is held between deliveries is one incomplete block or nothing.
      # A refusal ends the walk, there being no state to hand the next piece to.
      Enum.reduce_while(pieces, Pcapng.new(), fn piece, decoder ->
        case Pcapng.decode(decoder, piece) do
          {:ok, blocks, next} ->
            assert is_list(blocks)
            assert Pcapng.buffered(next) <= Pcapng.max_block_bytes()
            {:cont, next}

          {:error, reason} ->
            named(label, reason)
            {:halt, :refused}
        end
      end)

      generator
    end)
  end

  defp answered(label, bytes) do
    case Pcapng.decode(Pcapng.new(), bytes) do
      {:ok, blocks, decoder} ->
        assert is_list(blocks)

        # Whatever was not decoded is one block still arriving, and the bound on
        # that is this decoder's own rather than the sender's.
        assert Pcapng.buffered(decoder) <= Pcapng.max_block_bytes(),
               "#{label} held more than one block's worth"

      {:error, reason} ->
        named(label, reason)
    end
  end

  defp named(label, reason) do
    assert is_tuple(reason), "#{label} refused with #{inspect(reason)}, which is not a reason"
    tag = elem(reason, 0)

    assert MapSet.member?(@tags, tag),
           "#{label} refused under #{inspect(tag)}, a tag this build does not name"

    description = Pcapng.describe(reason)

    # `describe/1` is typed as a string, so asserting that it is one asserts
    # nothing. What is worth holding is that the operator holding a broken
    # recording is given words rather than the raw term.
    refute description == "",
           "#{label} refused under #{inspect(tag)} with nothing an operator could read"

    refute description == inspect(reason),
           "#{label} refused under #{inspect(tag)} with the term itself where a sentence belongs"
  end

  # Seeded, so a failure names bytes anybody can rebuild rather than bytes that
  # happened once.
  defp cases do
    generator = :rand.seed_s(:exsss, {@seed, 1, 1})
    fixtures = Enum.map(RecordingFixtures.names(), &RecordingFixtures.read!/1)

    {noise, generator} = noise(generator)
    {flipped, _generator} = flipped(fixtures, generator)

    noise ++ prefixes(fixtures) ++ flipped
  end

  # Bytes with no structure at all, including the lengths where a decision is
  # made on partial framing: nothing, a type, a type and a length, a whole header.
  defp noise(generator) do
    Enum.map_reduce(sizes(), generator, fn size, generator ->
      {bytes, generator} =
        Enum.map_reduce(1..max(size, 1)//1, generator, fn _index, generator ->
          {byte, generator} = :rand.uniform_s(256, generator)
          {byte - 1, generator}
        end)

      {{"#{size} bytes of noise", :binary.list_to_bin(Enum.take(bytes, size))}, generator}
    end)
  end

  defp sizes, do: [0, 1, 2, 3, 4, 7, 8, 11, 12, 13, 16, 28, 32, 64, 129, 512, 1024, 4096]

  # Every prefix of a real recording is a recording that has not all arrived, and
  # every one of them has to be answered as such.
  defp prefixes(fixtures) do
    for {bytes, index} <- Enum.with_index(fixtures),
        length <- 0..byte_size(bytes)//13 do
      {"fixture #{index} truncated to #{length}", binary_part(bytes, 0, length)}
    end
  end

  # One byte of a real recording, taken to a value it did not have. This is the
  # case that reaches the option walks and the payload arithmetic, because
  # everything ahead of the flipped byte is genuinely well formed.
  defp flipped(fixtures, generator) do
    Enum.map_reduce(1..600, generator, fn index, generator ->
      {choice, generator} = :rand.uniform_s(Enum.count(fixtures), generator)
      bytes = Enum.at(fixtures, choice - 1)
      {at, generator} = :rand.uniform_s(byte_size(bytes), generator)
      {value, generator} = :rand.uniform_s(256, generator)

      broken = RecordingFixtures.patch(bytes, at - 1, <<value - 1>>)

      {{"fixture #{choice - 1} byte #{at - 1} set to #{value - 1} (case #{index})", broken},
       generator}
    end)
  end

  # Split a byte string into pieces of arbitrary size, the way a transport would.
  defp cut(bytes, generator), do: cut(bytes, generator, [])

  defp cut(<<>>, generator, pieces), do: {Enum.reverse(pieces), generator}

  defp cut(bytes, generator, pieces) do
    {size, generator} = :rand.uniform_s(min(byte_size(bytes), 97), generator)
    <<piece::binary-size(^size), rest::binary>> = bytes
    cut(rest, generator, [piece | pieces])
  end
end
