defmodule Ctrld.RecordingFixtures do
  @moduledoc """
  The committed recordings, and the two ways a test needs to look at them.

  The fixtures are recordings the appliance's own encoder wrote, taken off the
  medium a QEMU boot left behind and committed unchanged. `metric-readings-logs`
  is the one that carries the appliance's metric readings: a connection history
  from a boot long enough to have published several, so the whole path from a
  Custom Block to a `metric_samples` row is driven by bytes this server did not
  compose. They are the reason
  this decoder is tested at all rather than merely exercised: bytes a helper here
  produced would only ever prove that this reader agrees with this reader.

  So the helpers below do two things and deliberately not a third. They read a
  fixture, and they locate and overwrite bytes within one — which is how a
  refusal is driven by a real recording with one field broken, rather than by a
  blob assembled to fail. What they do not do is compose a recording, except for
  the two shapes no recording contains: an Interface Statistics Block, which the
  appliance's encoder can write and its recorder never does, and a big-endian
  section, which an appliance running on one architecture cannot produce. Those
  two are built from the format's own rules, and each test that uses one says so.
  """

  @directory Path.join(__DIR__, "fixtures")

  @section_header 0x0A0D_0D0A
  @framing 12

  @doc "The fixtures, by the names the tests know them under."
  @spec names() :: [String.t()]
  def names,
    do: ~w(channel-established-logs channel-established-capture policy-revocation-logs
         metric-readings-logs)

  @doc "One fixture's bytes."
  @spec read!(String.t()) :: binary()
  def read!(name), do: File.read!(Path.join(@directory, name <> ".pcapng"))

  @doc """
  Where every block in a recording begins, as `{type, offset, total}` in order.

  Read here with the same little-endian framing the appliance writes and
  nothing else, because its only job is to aim a mutation at a field. A fixture
  this walk cannot get to the end of would be a mis-copied file, so it raises
  rather than answering a partial list.
  """
  @spec blocks(binary()) :: [{non_neg_integer(), non_neg_integer(), pos_integer()}]
  def blocks(bytes), do: walk(bytes, 0, [])

  @doc "The first block of `type`, as `{offset, total}`."
  @spec block!(binary(), non_neg_integer()) :: {non_neg_integer(), pos_integer()}
  def block!(bytes, type) do
    {^type, offset, total} = Enum.find(blocks(bytes), fn {found, _, _} -> found == type end)
    {offset, total}
  end

  @doc "The `index`th block of `type`, as `{offset, total}`, counting from zero."
  @spec block!(binary(), non_neg_integer(), non_neg_integer()) ::
          {non_neg_integer(), pos_integer()}
  def block!(bytes, type, index) do
    {^type, offset, total} =
      bytes |> blocks() |> Enum.filter(fn {found, _, _} -> found == type end) |> Enum.at(index)

    {offset, total}
  end

  @doc """
  Replace the bytes at `offset` with `replacement`, keeping the length.

  Length-preserving on purpose: a mutation that resized the stream would move
  every later block and could not be said to have broken one field.
  """
  @spec patch(binary(), non_neg_integer(), binary()) :: binary()
  def patch(bytes, offset, replacement) do
    size = byte_size(replacement)
    ^size = byte_size(binary_part(bytes, offset, size))

    binary_part(bytes, 0, offset) <>
      replacement <>
      binary_part(bytes, offset + size, byte_size(bytes) - offset - size)
  end

  @doc "A little-endian 32-bit field, for patching a length or a count."
  @spec u32(non_neg_integer()) :: binary()
  def u32(value), do: <<value::unsigned-little-32>>

  @doc "Where a block's option area begins, given the block and its fixed body."
  @spec options_at(non_neg_integer(), non_neg_integer()) :: non_neg_integer()
  def options_at(offset, body_length), do: offset + 8 + body_length

  @doc """
  Where an Enhanced Packet Block's options begin, past its payload and padding.
  """
  @spec packet_options_at(binary(), non_neg_integer()) :: non_neg_integer()
  def packet_options_at(bytes, offset) do
    <<captured::unsigned-little-32>> = binary_part(bytes, offset + 8 + 12, 4)
    options_at(offset, 20 + captured + padding_for(captured))
  end

  @doc """
  An Interface Statistics Block, in a section that describes one interface.

  Synthesised, because the appliance's recorder writes none: it reports loss
  through each record's drop count instead. The layout is the encoder's — the
  interface, the timestamp's two halves high word first, and the four counts as
  options, the two times as halves of their own rather than as plain 64-bit
  numbers.
  """
  @spec statistics_stream() :: binary()
  def statistics_stream do
    section(:little) <>
      interface(:little) <>
      block(
        :little,
        0x0000_0005,
        <<0::unsigned-little-32>> <>
          halves(:little, 1_700_000_000_000_000) <>
          options(:little, [
            {2, halves(:little, 1_600_000_000_000_000)},
            {3, halves(:little, 1_700_000_000_000_000)},
            {4, <<4321::unsigned-little-64>>},
            {5, <<7::unsigned-little-64>>}
          ])
      )
  end

  @doc """
  The smallest recording a big-endian writer would produce: a section, one
  interface, and one record carrying a drop count.

  Synthesised, because the appliance is little-endian only — it runs on one
  architecture and writes the byte-order magic rather than choosing it. The path
  exists because the format has it and a section states which order it used, so
  what is under test here is the format's rule and not the appliance's habit.
  """
  @spec big_endian_stream() :: binary()
  def big_endian_stream do
    section(:big) <> interface(:big) <> packet(:big)
  end

  @doc "The instant `big_endian_stream/0`'s record carries."
  @spec big_endian_observed_at() :: DateTime.t()
  def big_endian_observed_at, do: DateTime.from_unix!(1_786_402_605_043_072, :microsecond)

  @doc "The drop count `big_endian_stream/0`'s record carries."
  @spec big_endian_drop_count() :: pos_integer()
  def big_endian_drop_count, do: 9

  defp section(endianness) do
    magic =
      if endianness == :little, do: <<0x4D, 0x3C, 0x2B, 0x1A>>, else: <<0x1A, 0x2B, 0x3C, 0x4D>>

    body =
      magic <>
        uint(endianness, 1, 2) <>
        uint(endianness, 0, 2) <>
        uint(endianness, 0xFFFF_FFFF_FFFF_FFFF, 8)

    block(endianness, @section_header, body)
  end

  defp interface(endianness) do
    body = uint(endianness, 1, 2) <> uint(endianness, 0, 2) <> uint(endianness, 128, 4)
    block(endianness, 0x0000_0001, body <> options(endianness, [{9, <<6>>}]))
  end

  defp packet(endianness) do
    frame = <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE>>

    body =
      uint(endianness, 0, 4) <>
        halves(endianness, 1_786_402_605_043_072) <>
        uint(endianness, byte_size(frame), 4) <>
        uint(endianness, byte_size(frame), 4) <>
        frame <>
        <<0::size(padding_for(byte_size(frame)) * 8)>>

    block(
      endianness,
      0x0000_0006,
      body <> options(endianness, [{4, uint(endianness, big_endian_drop_count(), 8)}])
    )
  end

  # A block is its type, its length, its body and its length again — and the
  # length counts all four, which is why it is computed from the body rather than
  # stated beside it.
  defp block(endianness, type, body) do
    total = @framing + byte_size(body)
    uint(endianness, type, 4) <> uint(endianness, total, 4) <> body <> uint(endianness, total, 4)
  end

  # An option area ends with the terminator, exactly as the appliance's encoder
  # emits it. A block with no option gets no area at all, which is why the
  # section below is built without calling this.
  defp options(endianness, options) do
    Enum.map_join(options, "", fn {code, value} ->
      uint(endianness, code, 2) <>
        uint(endianness, byte_size(value), 2) <>
        value <>
        <<0::size(padding_for(byte_size(value)) * 8)>>
    end) <> uint(endianness, 0, 2) <> uint(endianness, 0, 2)
  end

  # The format's two 32-bit halves, high word first — never one 64-bit number.
  defp halves(endianness, ticks) do
    uint(endianness, div(ticks, 0x1_0000_0000), 4) <>
      uint(endianness, rem(ticks, 0x1_0000_0000), 4)
  end

  defp uint(:little, value, width), do: <<value::unsigned-little-size(width * 8)>>
  defp uint(:big, value, width), do: <<value::unsigned-big-size(width * 8)>>

  defp padding_for(length), do: rem(4 - rem(length, 4), 4)

  defp walk(bytes, offset, acc) when byte_size(bytes) == offset, do: Enum.reverse(acc)

  defp walk(bytes, offset, acc) do
    <<type::unsigned-little-32, total::unsigned-little-32>> = binary_part(bytes, offset, 8)
    true = total >= @framing and offset + total <= byte_size(bytes)
    walk(bytes, offset + total, [{type, offset, total} | acc])
  end
end
