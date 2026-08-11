defmodule Ctrld.Telemetry.FiveTupleTest do
  @moduledoc """
  The five columns read out of a recorded frame's own headers.

  The frames here are the ones the appliance actually recorded, taken from the
  committed fixtures, plus the malformations a hostile network can put on a
  wire. Both matter: the first says the reader agrees with what a real capture
  holds, the second that it says no by name rather than by raising.
  """

  use ExUnit.Case, async: true

  alias Ctrld.{Pcapng, RecordingFixtures}
  alias Ctrld.Pcapng.Packet
  alias Ctrld.Telemetry.FiveTuple

  # One of the frames the revocation fixture holds: UDP from 10.0.0.2:4444 to
  # 10.0.1.2:5000, over Ethernet II.
  defp frame(fixture \\ "policy-revocation-logs", index \\ 0) do
    {:ok, blocks, _decoder} = Pcapng.decode(Pcapng.new(), RecordingFixtures.read!(fixture))

    blocks
    |> Enum.filter(&match?(%Packet{}, &1))
    |> Enum.at(index)
    |> Map.fetch!(:data)
  end

  describe "a frame the appliance recorded" do
    test "reads as the conversation it was" do
      assert {:ok, tuple} = FiveTuple.read(frame())

      assert tuple.protocol == 17
      assert tuple.source_address == {10, 0, 0, 2}
      assert tuple.destination_address == {10, 0, 1, 2}
      assert tuple.source_port == 4444
      assert tuple.destination_port == 5000
    end

    test "reads the reply with its ends the other way round" do
      assert {:ok, tuple} = FiveTuple.read(frame("policy-revocation-logs", 2))

      assert tuple.source_address == {10, 0, 1, 2}
      assert tuple.destination_address == {10, 0, 0, 2}
      assert tuple.source_port == 5000
      assert tuple.destination_port == 4444
    end

    test "every frame in every fixture is read" do
      for name <- RecordingFixtures.names() do
        {:ok, blocks, _decoder} = Pcapng.decode(Pcapng.new(), RecordingFixtures.read!(name))

        for %Packet{data: data} <- blocks, data != <<>> do
          assert {:ok, %FiveTuple{}} = FiveTuple.read(data),
                 "#{name} holds a frame this reader refuses"
        end
      end
    end
  end

  describe "a record about no frame" do
    test "is its own refusal rather than a truncation" do
      assert FiveTuple.read(<<>>) == {:error, :no_frame}
    end

    test "is what the revocation the appliance recorded carries" do
      {:ok, blocks, _decoder} =
        Pcapng.decode(Pcapng.new(), RecordingFixtures.read!("policy-revocation-logs"))

      revocation = Enum.find(blocks, &match?(%Packet{data: <<>>}, &1))

      assert %Packet{original_length: 0} = revocation
      assert FiveTuple.read(revocation.data) == {:error, :no_frame}
    end
  end

  describe "a frame that is not one" do
    test "below an Ethernet header is refused with what it had" do
      assert FiveTuple.read(<<0::13*8>>) == {:error, {:shorter_than_ethernet, 13}}
    end

    test "carrying something other than IPv4 names the EtherType" do
      # 0x86DD is IPv6, which this appliance's schema has no columns for.
      assert FiveTuple.read(ethernet(0x86DD, <<0::20*8>>)) ==
               {:error, {:not_ipv4_ethertype, 0x86DD}}
    end

    test "claiming IPv4 with too little behind it is refused" do
      assert FiveTuple.read(ethernet(0x0800, <<0x45, 0::18*8>>)) ==
               {:error, {:shorter_than_ipv4, 19}}
    end

    test "declaring IPv4 and opening on another version is refused" do
      assert FiveTuple.read(ethernet(0x0800, ipv4(version: 6))) == {:error, {:not_ipv4, 6}}
    end

    test "with a header below the minimum is refused" do
      assert FiveTuple.read(ethernet(0x0800, ipv4(words: 4))) ==
               {:error, {:header_below_minimum, 16}}
    end

    test "with a header longer than the bytes captured is refused" do
      assert FiveTuple.read(ethernet(0x0800, ipv4(words: 15))) ==
               {:error, {:header_exceeds_frame, 60, 24}}
    end

    test "that is a later fragment has no ports to read" do
      assert FiveTuple.read(ethernet(0x0800, ipv4(fragment_offset: 185))) ==
               {:error, {:later_fragment, 185}}
    end

    test "cut short of its port pair is refused with what was left" do
      assert FiveTuple.read(ethernet(0x0800, ipv4(payload: <<1, 2, 3>>))) ==
               {:error, {:shorter_than_ports, 17, 3}}
    end
  end

  describe "a protocol with no ports" do
    test "keeps its addresses and carries zero ports" do
      assert {:ok, tuple} = FiveTuple.read(ethernet(0x0800, ipv4(protocol: 1, payload: <<8, 0>>)))

      assert tuple.protocol == 1
      assert tuple.source_address == {10, 0, 0, 2}
      assert tuple.source_port == 0
      assert tuple.destination_port == 0
    end

    test "is still told apart from a frame that could not be read" do
      assert {:ok, tuple} = FiveTuple.read(ethernet(0x0800, ipv4(protocol: 1, payload: <<>>)))

      refute tuple.protocol == FiveTuple.unread_protocol()
      assert FiveTuple.absent().protocol == FiveTuple.unread_protocol()
    end
  end

  describe "the value a row carries where the frame could not be read" do
    test "is zero everywhere, and its protocol is one no read frame can hold" do
      absent = FiveTuple.absent()

      assert absent.protocol == 0
      assert absent.source_address == {0, 0, 0, 0}
      assert absent.destination_address == {0, 0, 0, 0}
      assert absent.source_port == 0
      assert absent.destination_port == 0
    end
  end

  describe "refusals" do
    test "every one renders as a sentence" do
      for refusal <- [
            :no_frame,
            {:shorter_than_ethernet, 3},
            {:not_ipv4_ethertype, 0x86DD},
            {:shorter_than_ipv4, 4},
            {:not_ipv4, 6},
            {:header_below_minimum, 16},
            {:header_exceeds_frame, 60, 28},
            {:later_fragment, 185},
            {:shorter_than_ports, 6, 2}
          ] do
        assert is_binary(FiveTuple.describe(refusal))
      end
    end
  end

  defp ethernet(ethertype, payload) do
    <<0x52, 0x54, 0x00, 0x12, 0x34, 0x50, 0x52, 0x54, 0x00, 0x00, 0x00, 0x0A,
      ethertype::unsigned-big-16>> <> payload
  end

  # An IPv4 header with every field at a value a real one carries, and whichever
  # of them the case under test needs moved.
  defp ipv4(options) do
    version = Keyword.get(options, :version, 4)
    words = Keyword.get(options, :words, 5)
    protocol = Keyword.get(options, :protocol, 17)
    fragment_offset = Keyword.get(options, :fragment_offset, 0)
    payload = Keyword.get(options, :payload, <<0x11, 0x5C, 0x13, 0x88>>)

    <<version::4, words::4, 0::8, 40::unsigned-big-16, 0::unsigned-big-16, 0::3,
      fragment_offset::13, 64::8, protocol::8, 0::unsigned-big-16, 10, 0, 0, 2, 10, 0, 1, 2>> <>
      payload
  end
end
