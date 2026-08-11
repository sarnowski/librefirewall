defmodule Ctrld.PcapngStreamTest do
  @moduledoc """
  The property a streaming decoder lives or dies by: where the bytes were cut
  must not be visible in what comes out.

  A recording arrives as whatever pieces the transport had, and a block spans
  them freely — the appliance flushes accumulated ring bytes on a period, not on
  a block boundary, and TLS records and TCP segments know nothing about either.
  So the interesting failure is not a block this decoder cannot read; it is a
  block it reads differently, or half-reads, because of where a delivery ended.

  These tests therefore take a real recording and feed it in every arrangement a
  transport could produce: whole, cut once at every offset there is, and one byte
  at a time. Every arrangement must yield the identical block sequence. Two
  further properties come with it — that nothing is ever taken past the block
  being decoded, which the byte-at-a-time run proves by never producing a block
  before its last byte has arrived, and that what is held between calls stays
  inside the bound this decoder publishes.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Pcapng
  alias Ctrld.RecordingFixtures

  describe "one cut, at every offset" do
    test "yields the same blocks wherever a delivery ends" do
      for name <- RecordingFixtures.names() do
        bytes = RecordingFixtures.read!(name)
        expected = whole(bytes)

        for split <- 0..byte_size(bytes) do
          <<head::binary-size(^split), tail::binary>> = bytes

          assert {:ok, first, decoder} = Pcapng.decode(Pcapng.new(), head)
          assert {:ok, second, decoder} = Pcapng.decode(decoder, tail)

          assert first ++ second == expected,
                 "#{name} decoded differently when cut at #{split}"

          assert Pcapng.buffered(decoder) == 0,
                 "#{name} held a partial block after the whole of it arrived, cut at #{split}"
        end
      end
    end
  end

  describe "a byte at a time" do
    test "produces each block exactly once, and never before its last byte" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      expected = whole(bytes)

      {decoded, decoder} =
        Enum.reduce(byte_list(bytes), {[], Pcapng.new()}, fn byte, {decoded, decoder} ->
          assert {:ok, blocks, decoder} = Pcapng.decode(decoder, byte)
          {decoded ++ blocks, decoder}
        end)

      assert decoded == expected
      assert Pcapng.buffered(decoder) == 0
    end

    test "answers a held block only once the byte completing it arrives" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      [{_type, _offset, first_total} | _] = RecordingFixtures.blocks(bytes)

      # One byte short of the section header, nothing can be answered: the block
      # is held rather than guessed at from the fields that did arrive.
      short = binary_part(bytes, 0, first_total - 1)
      assert {:ok, [], decoder} = Pcapng.decode(Pcapng.new(), short)
      assert Pcapng.buffered(decoder) == first_total - 1

      # The byte that completes it is the byte that produces it, and nothing is
      # taken past it into the block that follows.
      last = binary_part(bytes, first_total - 1, 1)
      assert {:ok, [section], decoder} = Pcapng.decode(decoder, last)
      assert %Pcapng.Section{} = section
      assert Pcapng.buffered(decoder) == 0
    end
  end

  describe "asking again" do
    test "an empty delivery answers no blocks and holds what it held" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      short = binary_part(bytes, 0, 20)

      assert {:ok, [], held} = Pcapng.decode(Pcapng.new(), short)
      assert {:ok, [], ^held} = Pcapng.decode(held, <<>>)
      assert Pcapng.buffered(held) == 20
    end

    test "a stream that has ended mid-block simply never completes it" do
      bytes = RecordingFixtures.read!("policy-revocation-logs")

      # Every truncation of a recording is a recording that has not all arrived,
      # never a malformed one: a reader cannot tell a slow sender from a short
      # file, and must not refuse either.
      for length <- 0..64 do
        assert {:ok, _blocks, _decoder} =
                 Pcapng.decode(Pcapng.new(), binary_part(bytes, 0, length))
      end
    end
  end

  describe "the buffer bound" do
    test "never holds more than one block's worth, whatever arrives" do
      for name <- RecordingFixtures.names() do
        bytes = RecordingFixtures.read!(name)
        largest = bytes |> RecordingFixtures.blocks() |> Enum.map(&elem(&1, 2)) |> Enum.max()

        for split <- 0..byte_size(bytes) do
          {:ok, _blocks, decoder} = Pcapng.decode(Pcapng.new(), binary_part(bytes, 0, split))

          # What is held is the block still arriving and nothing else — so the
          # peak is bounded by the largest block, itself bounded by what this
          # decoder will accept a declared length of.
          assert Pcapng.buffered(decoder) < largest + 1
          assert Pcapng.buffered(decoder) <= Pcapng.max_block_bytes()
        end
      end
    end
  end

  describe "two sections in one stream" do
    test "are decoded as the boundary they are, each renumbering its interfaces" do
      # A recording is a ring of segments and every segment opens a section, so a
      # stream carrying more than one is the ordinary case rather than an edge.
      first = RecordingFixtures.read!("channel-established-logs")
      second = RecordingFixtures.read!("policy-revocation-logs")

      assert {:ok, blocks, decoder} = Pcapng.decode(Pcapng.new(), first <> second)
      assert Pcapng.buffered(decoder) == 0
      assert blocks == whole(first) ++ whole(second)

      sections = Enum.count(blocks, &match?(%Pcapng.Section{}, &1))
      assert sections == 2

      # The numbering restarts, so the second section's ports are 0 and 1 again
      # rather than continuing from the first section's.
      assert blocks |> Enum.filter(&match?(%Pcapng.Interface{}, &1)) |> Enum.map(& &1.id) ==
               [0, 1, 0, 1]
    end
  end

  defp whole(bytes) do
    assert {:ok, blocks, decoder} = Pcapng.decode(Pcapng.new(), bytes)
    assert Pcapng.buffered(decoder) == 0
    blocks
  end

  defp byte_list(bytes), do: for(<<byte <- bytes>>, do: <<byte>>)
end
