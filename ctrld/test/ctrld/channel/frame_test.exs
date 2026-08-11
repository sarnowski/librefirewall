defmodule Ctrld.Channel.FrameTest do
  @moduledoc """
  The codec against the bytes the contract fixes.

  Every assertion in the wire-bytes section states a literal binary rather than
  building one through the encoder, because a test that composed its expectation
  the way the code does would agree with the code however wrong both were. The
  appliance's own codec is the other implementation of these same bytes, so what
  is pinned here is the one thing neither end may decide alone.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Channel.Frame

  # The greeting each end sends, spelled out once: two bytes of version, and for
  # the server the two resume cursors behind it.
  @appliance_hello <<0, 0, 0, 2, 0x01, 0, 0, 0, 0, 1>>
  @server_hello <<0, 0, 0, 18, 0x01, 0, 0, 0, 0, 1, 0::64, 0::64>>

  defp wire(sender, frame) do
    assert {:ok, bytes} = Frame.encode(sender, frame)
    IO.iodata_to_binary(bytes)
  end

  defp decoded(sender, <<_length::32, kind, 0, 0, 0, payload::binary>>) do
    assert {:ok, type} = Frame.type_from_byte(kind)
    Frame.read_payload(type, sender, payload)
  end

  defp header(payload_length, type_byte, reserved \\ <<0, 0, 0>>) do
    <<payload_length::unsigned-big-integer-32, type_byte, reserved::binary>>
  end

  describe "the header" do
    test "states the payload length big-endian, the type byte, and three zeroes" do
      assert <<0, 0, 0, 2, 0x01, 0, 0, 0, _payload::binary>> =
               wire(:appliance, {:hello, :appliance})

      assert <<0, 0, 1, 0, 0x02, 0, 0, 0, _payload::binary>> =
               wire(:appliance, {:up_records, 0, :binary.copy(<<0>>, 248)})
    end

    test "is eight bytes, and the payload bound is a mebibyte" do
      assert Frame.header_length() == 8
      assert Frame.max_payload_length() == 1_048_576
      assert Frame.max_document_length() == 65_536
      assert Frame.version() == 1
    end
  end

  describe "the type bytes" do
    test "run one through ten with no gap, and round-trip" do
      for {type, index} <- Enum.with_index(Frame.all_types(), 1) do
        assert Frame.type_byte(type) == index
        assert Frame.type_from_byte(index) == {:ok, type}
      end

      assert length(Frame.all_types()) == 10
    end

    test "name no frame at zero or past the last" do
      assert Frame.type_from_byte(0) == :error
      assert Frame.type_from_byte(11) == :error
      assert Frame.type_from_byte(255) == :error
    end
  end

  describe "direction" do
    test "the greeting travels both ways and every other frame one way" do
      assert Frame.may_travel_from?(:hello, :appliance)
      assert Frame.may_travel_from?(:hello, :server)

      for type <- [:up_records, :up_capture, :up_config_validate_result, :up_range_data] do
        assert Frame.may_travel_from?(type, :appliance)
        refute Frame.may_travel_from?(type, :server)
      end

      for type <- [
            :ack,
            :down_config_stage,
            :down_config_commit,
            :down_commit_confirm,
            :down_range_read
          ] do
        assert Frame.may_travel_from?(type, :server)
        refute Frame.may_travel_from?(type, :appliance)
      end
    end

    test "every frame travels from at least one end" do
      for type <- Frame.all_types() do
        assert Frame.may_travel_from?(type, :appliance) or Frame.may_travel_from?(type, :server)
      end
    end
  end

  describe "the payload floors" do
    # Stated as literals rather than derived, because what they are held to is the
    # appliance's own codec: these ten numbers are the other end's `payload_floor`
    # field for field, and a floor that drifted would have both ends reporting a
    # different `needed` for the same refused frame.
    test "are the numbers each frame's fields need" do
      assert Frame.payload_floor(:hello, :appliance) == 2
      assert Frame.payload_floor(:hello, :server) == 18
      assert Frame.payload_floor(:up_records, :appliance) == 8
      assert Frame.payload_floor(:up_capture, :appliance) == 8
      assert Frame.payload_floor(:ack, :server) == 16
      assert Frame.payload_floor(:down_config_stage, :server) == 0
      assert Frame.payload_floor(:up_config_validate_result, :appliance) == 1
      assert Frame.payload_floor(:down_config_commit, :server) == 10
      assert Frame.payload_floor(:down_commit_confirm, :server) == 8
      assert Frame.payload_floor(:down_range_read, :server) == 17
      assert Frame.payload_floor(:up_range_data, :appliance) == 10
    end

    test "depend on the sending end for the greeting alone" do
      for type <- Frame.all_types() -- [:hello] do
        assert Frame.payload_floor(type, :appliance) == Frame.payload_floor(type, :server)
      end

      refute Frame.payload_floor(:hello, :appliance) == Frame.payload_floor(:hello, :server)
    end
  end

  describe "the greeting on the wire" do
    test "the appliance's carries the version and nothing else" do
      assert wire(:appliance, {:hello, :appliance}) == @appliance_hello
      assert decoded(:appliance, @appliance_hello) == {:ok, {:hello, :appliance}}
    end

    test "the server's carries the version and the two resume cursors" do
      assert wire(:server, {:hello, {:server, 0, 0}}) == @server_hello
      assert decoded(:server, @server_hello) == {:ok, {:hello, {:server, 0, 0}}}
    end

    test "the cursors are big-endian and independent" do
      assert wire(:server, {:hello, {:server, 1, 0x0102_0304_0506_0708}}) ==
               <<0, 0, 0, 18, 0x01, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7,
                 8>>
    end

    test "neither end may compose the other's" do
      assert Frame.encode(:appliance, {:hello, {:server, 0, 0}}) ==
               {:error, {:wrong_direction, :hello, :appliance}}

      assert Frame.encode(:server, {:hello, :appliance}) ==
               {:error, {:wrong_direction, :hello, :server}}
    end
  end

  describe "the upstream frames on the wire" do
    test "up_records is a ring position then the ring bytes, verbatim" do
      assert wire(:appliance, {:up_records, 7, "pcapng"}) ==
               <<0, 0, 0, 14, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, "pcapng">>

      assert decoded(:appliance, <<0, 0, 0, 14, 0x02, 0, 0, 0, 0::56, 7, "pcapng">>) ==
               {:ok, {:up_records, 7, "pcapng"}}
    end

    test "up_capture is the same shape under its own type byte" do
      assert wire(:appliance, {:up_capture, 7, "pcapng"}) ==
               <<0, 0, 0, 14, 0x03, 0, 0, 0, 0::56, 7, "pcapng">>

      assert decoded(:appliance, <<0, 0, 0, 14, 0x03, 0, 0, 0, 0::56, 7, "pcapng">>) ==
               {:ok, {:up_capture, 7, "pcapng"}}
    end

    test "either carries no bytes at all, a position being whole information" do
      assert wire(:appliance, {:up_records, 0, <<>>}) == <<0, 0, 0, 8, 0x02, 0, 0, 0, 0::64>>

      assert decoded(:appliance, <<0, 0, 0, 8, 0x02, 0, 0, 0, 0::64>>) ==
               {:ok, {:up_records, 0, <<>>}}
    end

    test "a validate result is one line of printable ASCII" do
      line = "generation=3 outcome=accepted"

      assert wire(:appliance, {:up_config_validate_result, line}) ==
               <<0, 0, 0, 29, 0x06, 0, 0, 0, line::binary>>

      assert decoded(:appliance, <<0, 0, 0, 29, 0x06, 0, 0, 0, line::binary>>) ==
               {:ok, {:up_config_validate_result, line}}
    end

    test "range data is a ring, a status, a position, then the bytes" do
      assert wire(:appliance, {:up_range_data, :capture, :data, 4096, "bytes"}) ==
               <<0, 0, 0, 15, 0x0A, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, "bytes">>

      assert decoded(:appliance, <<0, 0, 0, 15, 0x0A, 0, 0, 0, 1, 0, 4096::64, "bytes">>) ==
               {:ok, {:up_range_data, :capture, :data, 4096, "bytes"}}
    end

    test "a range answer that ended carries no bytes" do
      assert wire(:appliance, {:up_range_data, :log, :overwritten, 0, <<>>}) ==
               <<0, 0, 0, 10, 0x0A, 0, 0, 0, 0, 1, 0::64>>

      assert wire(:appliance, {:up_range_data, :log, :medium_refused, 0, <<>>}) ==
               <<0, 0, 0, 10, 0x0A, 0, 0, 0, 0, 2, 0::64>>
    end
  end

  describe "the downstream frames on the wire" do
    test "an acknowledgement is two cursors, log then capture" do
      assert wire(:server, {:ack, 1, 2}) == <<0, 0, 0, 16, 0x04, 0, 0, 0, 1::64, 2::64>>
      assert decoded(:server, <<0, 0, 0, 16, 0x04, 0, 0, 0, 1::64, 2::64>>) == {:ok, {:ack, 1, 2}}
    end

    test "a config stage is the document and nothing else" do
      assert wire(:server, {:down_config_stage, "<firewall/>"}) ==
               <<0, 0, 0, 11, 0x05, 0, 0, 0, "<firewall/>">>

      assert decoded(:server, <<0, 0, 0, 11, 0x05, 0, 0, 0, "<firewall/>">>) ==
               {:ok, {:down_config_stage, "<firewall/>"}}
    end

    test "an empty document is a frame this codec composes and hands on" do
      assert wire(:server, {:down_config_stage, <<>>}) == <<0, 0, 0, 0, 0x05, 0, 0, 0>>
      assert decoded(:server, <<0, 0, 0, 0, 0x05, 0, 0, 0>>) == {:ok, {:down_config_stage, <<>>}}
    end

    test "a commit is a generation and a deadline in seconds" do
      assert wire(:server, {:down_config_commit, 9, 600}) ==
               <<0, 0, 0, 10, 0x07, 0, 0, 0, 9::64, 2, 88>>

      assert decoded(:server, <<0, 0, 0, 10, 0x07, 0, 0, 0, 9::64, 600::16>>) ==
               {:ok, {:down_config_commit, 9, 600}}
    end

    test "a commit confirmation is a generation" do
      assert wire(:server, {:down_commit_confirm, 9}) == <<0, 0, 0, 8, 0x08, 0, 0, 0, 9::64>>

      assert decoded(:server, <<0, 0, 0, 8, 0x08, 0, 0, 0, 9::64>>) ==
               {:ok, {:down_commit_confirm, 9}}
    end

    test "a range read is a ring, a start and a length" do
      assert wire(:server, {:down_range_read, :log, 0, 4096}) ==
               <<0, 0, 0, 17, 0x09, 0, 0, 0, 0, 0::64, 0, 0, 0, 0, 0, 0, 16, 0>>

      assert decoded(:server, <<0, 0, 0, 17, 0x09, 0, 0, 0, 1, 8::64, 4096::64>>) ==
               {:ok, {:down_range_read, :capture, 8, 4096}}
    end
  end

  describe "the closed byte vocabularies" do
    test "a ring selector is nought or one and nothing else" do
      assert Frame.ring_byte(:log) == 0
      assert Frame.ring_byte(:capture) == 1
      assert Frame.ring_from_byte(0) == {:ok, :log}
      assert Frame.ring_from_byte(1) == {:ok, :capture}
      assert Frame.ring_from_byte(2) == :error
      assert Frame.ring_from_byte(255) == :error
    end

    test "a range status is nought through two and nothing else" do
      assert Frame.range_status_byte(:data) == 0
      assert Frame.range_status_byte(:overwritten) == 1
      assert Frame.range_status_byte(:medium_refused) == 2
      assert Frame.range_status_from_byte(3) == :error
      refute Frame.ends_the_answer?(:data)
      assert Frame.ends_the_answer?(:overwritten)
      assert Frame.ends_the_answer?(:medium_refused)
    end
  end

  describe "refusing a header" do
    test "reserved_non_zero, naming which of the three" do
      assert Frame.read_header(header(0, 0x01, <<1, 0, 0>>), :appliance, false) ==
               {:error, {:reserved_non_zero, 0, 1}}

      assert Frame.read_header(header(0, 0x01, <<0, 2, 0>>), :appliance, false) ==
               {:error, {:reserved_non_zero, 1, 2}}

      assert Frame.read_header(header(0, 0x01, <<0, 0, 3>>), :appliance, false) ==
               {:error, {:reserved_non_zero, 2, 3}}
    end

    test "reserved bytes are read before anything else in the header" do
      # Every other rule is broken too: an unknown type, a length past the
      # bound, and no greeting yet. The reserved byte is still the answer.
      assert Frame.read_header(header(1_048_577, 0xFF, <<1, 1, 1>>), :appliance, false) ==
               {:error, {:reserved_non_zero, 0, 1}}
    end

    test "unknown_type" do
      assert Frame.read_header(header(0, 0x00), :appliance, false) ==
               {:error, {:unknown_type, 0x00}}

      assert Frame.read_header(header(0, 0x0B), :appliance, true) ==
               {:error, {:unknown_type, 0x0B}}
    end

    test "payload_too_long, at one byte past the bound" do
      assert Frame.read_header(header(1_048_576, 0x02), :appliance, true) ==
               {:ok, :up_records, 1_048_576}

      assert Frame.read_header(header(1_048_577, 0x02), :appliance, true) ==
               {:error, {:payload_too_long, 1_048_577}}

      assert Frame.read_header(header(0xFFFF_FFFF, 0x02), :appliance, true) ==
               {:error, {:payload_too_long, 0xFFFF_FFFF}}
    end

    test "wrong_direction, per frame the peer may not send" do
      for type <- [
            :ack,
            :down_config_stage,
            :down_config_commit,
            :down_commit_confirm,
            :down_range_read
          ] do
        assert Frame.read_header(header(0, Frame.type_byte(type)), :appliance, true) ==
                 {:error, {:wrong_direction, type, :appliance}}
      end

      for type <- [:up_records, :up_capture, :up_config_validate_result, :up_range_data] do
        assert Frame.read_header(header(0, Frame.type_byte(type)), :server, true) ==
                 {:error, {:wrong_direction, type, :server}}
      end
    end

    test "first_frame_not_hello" do
      assert Frame.read_header(header(8, 0x02), :appliance, false) ==
               {:error, {:first_frame_not_hello, :up_records}}

      assert Frame.read_header(header(8, 0x02), :appliance, true) == {:ok, :up_records, 8}
    end

    test "config_document_too_long, on its own bound and not the frame's" do
      assert Frame.read_header(header(65_536, 0x05), :server, true) ==
               {:ok, :down_config_stage, 65_536}

      assert Frame.read_header(header(65_537, 0x05), :server, true) ==
               {:error, {:config_document_too_long, 65_537}}

      # Still under the frame bound, so this is a different rule from
      # payload_too_long and says so.
      assert Frame.read_header(header(1_048_576, 0x05), :server, true) ==
               {:error, {:config_document_too_long, 1_048_576}}
    end
  end

  describe "refusing a payload" do
    test "version_mismatch, before the rest of the greeting's shape is judged" do
      assert Frame.read_payload(:hello, :appliance, <<2::16>>) ==
               {:error, {:version_mismatch, 2}}

      assert Frame.read_payload(:hello, :appliance, <<0::16>>) ==
               {:error, {:version_mismatch, 0}}

      # A version this end does not speak, on a payload that is also the wrong
      # length for either greeting: the version is still the answer.
      assert Frame.read_payload(:hello, :server, <<7::16, 1, 2, 3>>) ==
               {:error, {:version_mismatch, 7}}
    end

    test "payload_length on a greeting of the wrong shape for its end" do
      assert Frame.read_payload(:hello, :appliance, <<1::16, 0>>) ==
               {:error, {:payload_length, :hello, 3, 2}}

      assert Frame.read_payload(:hello, :server, <<1::16>>) ==
               {:error, {:payload_length, :hello, 2, 18}}

      assert Frame.read_payload(:hello, :appliance, <<>>) ==
               {:error, {:payload_length, :hello, 0, 2}}
    end

    test "payload_length on a payload that runs out mid-field" do
      assert Frame.read_payload(:up_records, :appliance, <<0, 0, 0>>) ==
               {:error, {:payload_length, :up_records, 3, 8}}

      assert Frame.read_payload(:ack, :server, <<0::64>>) ==
               {:error, {:payload_length, :ack, 8, 16}}

      assert Frame.read_payload(:down_config_commit, :server, <<0::64>>) ==
               {:error, {:payload_length, :down_config_commit, 8, 10}}

      assert Frame.read_payload(:down_range_read, :server, <<0, 0::64>>) ==
               {:error, {:payload_length, :down_range_read, 9, 17}}

      assert Frame.read_payload(:up_range_data, :appliance, <<0, 0, 0, 0>>) ==
               {:error, {:payload_length, :up_range_data, 4, 10}}
    end

    test "payload_length on trailing bytes past a fixed shape" do
      assert Frame.read_payload(:ack, :server, <<0::64, 0::64, 0>>) ==
               {:error, {:payload_length, :ack, 17, 16}}

      assert Frame.read_payload(:down_commit_confirm, :server, <<0::64, 0>>) ==
               {:error, {:payload_length, :down_commit_confirm, 9, 8}}

      assert Frame.read_payload(:down_range_read, :server, <<0, 0::64, 0::64, 0>>) ==
               {:error, {:payload_length, :down_range_read, 18, 17}}
    end

    test "payload_length on a validate result of no bytes at all" do
      assert Frame.read_payload(:up_config_validate_result, :appliance, <<>>) ==
               {:error, {:payload_length, :up_config_validate_result, 0, 1}}
    end

    test "unknown_ring, on both frames that select one" do
      assert Frame.read_payload(:down_range_read, :server, <<2, 0::64, 0::64>>) ==
               {:error, {:unknown_ring, 2}}

      assert Frame.read_payload(:up_range_data, :appliance, <<255, 0, 0::64>>) ==
               {:error, {:unknown_ring, 255}}
    end

    # The fields are read in order, so a vocabulary byte is judged where it sits
    # rather than after the whole payload has been measured. Both codecs of this
    # protocol do that, and an operator handed "the payload is the wrong length"
    # for a selector naming neither recording would be sent looking for a
    # truncated frame instead of a confused peer.
    test "unknown_ring ahead of the payload's own length" do
      assert Frame.read_payload(:down_range_read, :server, <<2>>) ==
               {:error, {:unknown_ring, 2}}

      assert Frame.read_payload(:up_range_data, :appliance, <<9>>) ==
               {:error, {:unknown_ring, 9}}
    end

    test "unknown_range_status" do
      assert Frame.read_payload(:up_range_data, :appliance, <<0, 3, 0::64>>) ==
               {:error, {:unknown_range_status, 3}}
    end

    test "unknown_range_status ahead of the payload's own length" do
      assert Frame.read_payload(:up_range_data, :appliance, <<1, 3>>) ==
               {:error, {:unknown_range_status, 3}}
    end

    # And the length still wins where the vocabulary bytes are admissible: a ring
    # and a status this protocol has, and then a payload that runs out.
    test "payload_length where the selectors are fine and the numbers are not" do
      assert Frame.read_payload(:down_range_read, :server, <<1>>) ==
               {:error, {:payload_length, :down_range_read, 1, 17}}

      assert Frame.read_payload(:up_range_data, :appliance, <<1, 2>>) ==
               {:error, {:payload_length, :up_range_data, 2, 10}}
    end

    test "bytes_on_ended_range" do
      assert Frame.read_payload(:up_range_data, :appliance, <<0, 1, 0::64, "no">>) ==
               {:error, {:bytes_on_ended_range, :overwritten, 2}}

      assert Frame.read_payload(:up_range_data, :appliance, <<1, 2, 0::64, "none">>) ==
               {:error, {:bytes_on_ended_range, :medium_refused, 4}}
    end

    test "result_line_not_printable, naming the offset" do
      assert Frame.read_payload(:up_config_validate_result, :appliance, "ok\n") ==
               {:error, {:result_line_not_printable, 2, 0x0A}}

      assert Frame.read_payload(:up_config_validate_result, :appliance, <<0x7F>>) ==
               {:error, {:result_line_not_printable, 0, 0x7F}}

      assert Frame.read_payload(:up_config_validate_result, :appliance, <<"ok", 0xC3, 0xA9>>) ==
               {:error, {:result_line_not_printable, 2, 0xC3}}
    end

    test "a space and a tilde are printable, the bytes either side of them are not" do
      assert Frame.read_payload(:up_config_validate_result, :appliance, <<0x20, 0x7E>>) ==
               {:ok, {:up_config_validate_result, <<0x20, 0x7E>>}}

      assert Frame.read_payload(:up_config_validate_result, :appliance, <<0x1F>>) ==
               {:error, {:result_line_not_printable, 0, 0x1F}}
    end
  end

  describe "refusing to encode" do
    test "wrong_direction, per frame this end may not send" do
      assert Frame.encode(:server, {:up_records, 0, <<>>}) ==
               {:error, {:wrong_direction, :up_records, :server}}

      assert Frame.encode(:appliance, {:ack, 0, 0}) ==
               {:error, {:wrong_direction, :ack, :appliance}}
    end

    test "payload_too_long, at one byte past the bound" do
      assert {:ok, _bytes} =
               Frame.encode(:appliance, {:up_records, 0, :binary.copy(<<0>>, 1_048_568)})

      assert Frame.encode(:appliance, {:up_records, 0, :binary.copy(<<0>>, 1_048_569)}) ==
               {:error, {:payload_too_long, 1_048_577}}
    end

    test "config_document_too_long, on its own bound" do
      assert {:ok, _bytes} =
               Frame.encode(:server, {:down_config_stage, :binary.copy(<<0x20>>, 65_536)})

      assert Frame.encode(:server, {:down_config_stage, :binary.copy(<<0x20>>, 65_537)}) ==
               {:error, {:config_document_too_long, 65_537}}
    end

    test "empty_result_line" do
      assert Frame.encode(:appliance, {:up_config_validate_result, <<>>}) ==
               {:error, :empty_result_line}
    end

    test "result_line_not_printable" do
      assert Frame.encode(:appliance, {:up_config_validate_result, "ok\n"}) ==
               {:error, {:result_line_not_printable, 2, 0x0A}}
    end

    test "bytes_on_ended_range" do
      assert Frame.encode(:appliance, {:up_range_data, :log, :overwritten, 0, "x"}) ==
               {:error, {:bytes_on_ended_range, :overwritten, 1}}
    end
  end

  describe "every frame round-trips" do
    test "one of each, in the direction it travels" do
      for {sender, frame} <- sample_frames() do
        bytes = wire(sender, frame)
        assert decoded(sender, bytes) == {:ok, frame}, "#{inspect(frame)} did not round-trip"
      end
    end

    test "every frame type is covered by the samples" do
      covered = sample_frames() |> Enum.map(fn {_sender, frame} -> Frame.frame_type(frame) end)
      assert Enum.sort(Enum.uniq(covered)) == Enum.sort(Frame.all_types())
    end

    # The property: an arbitrary frame of an arbitrary shape encodes to bytes
    # that decode back to exactly it. Generated from this protocol's own closed
    # vocabulary rather than from a library, so the generator cannot produce a
    # value the type system already excludes — and seeded per run, so a failure
    # arrives with the seed that produced it.
    test "an arbitrary frame decodes back to itself" do
      seed = :erlang.unique_integer([:positive])
      state = :rand.seed_s(:exsss, {seed, seed, seed})

      Enum.reduce(1..2_000, state, fn _iteration, state ->
        {sender, frame, state} = arbitrary_frame(state)
        bytes = wire(sender, frame)

        assert decoded(sender, bytes) == {:ok, frame},
               "seed #{seed}: #{inspect(frame)} did not round-trip"

        # The stated length is the payload's real length, which is what keeps
        # two ends agreeing about where the next frame starts.
        <<stated::unsigned-big-integer-32, _kind, 0, 0, 0, payload::binary>> = bytes
        assert stated == byte_size(payload)

        state
      end)
    end
  end

  defp sample_frames do
    [
      {:appliance, {:hello, :appliance}},
      {:server, {:hello, {:server, 1, 2}}},
      {:appliance, {:up_records, 1, "log"}},
      {:appliance, {:up_capture, 2, "capture"}},
      {:server, {:ack, 3, 4}},
      {:server, {:down_config_stage, "<firewall/>"}},
      {:appliance, {:up_config_validate_result, "generation=1 outcome=accepted"}},
      {:server, {:down_config_commit, 5, 6}},
      {:server, {:down_commit_confirm, 7}},
      {:server, {:down_range_read, :log, 8, 9}},
      {:appliance, {:up_range_data, :capture, :data, 10, "range"}}
    ]
  end

  @max_u64 0xFFFF_FFFF_FFFF_FFFF

  defp arbitrary_frame(state) do
    {index, state} = :rand.uniform_s(length(Frame.all_types()), state)

    case Enum.at(Frame.all_types(), index - 1) do
      :hello ->
        {which, state} = :rand.uniform_s(2, state)

        if which == 1 do
          {:appliance, {:hello, :appliance}, state}
        else
          {log, state} = number(state)
          {capture, state} = number(state)
          {:server, {:hello, {:server, log, capture}}, state}
        end

      :up_records ->
        {position, state} = number(state)
        {bytes, state} = blob(state)
        {:appliance, {:up_records, position, bytes}, state}

      :up_capture ->
        {position, state} = number(state)
        {bytes, state} = blob(state)
        {:appliance, {:up_capture, position, bytes}, state}

      :ack ->
        {log, state} = number(state)
        {capture, state} = number(state)
        {:server, {:ack, log, capture}, state}

      :down_config_stage ->
        {document, state} = blob(state)
        {:server, {:down_config_stage, document}, state}

      :up_config_validate_result ->
        {line, state} = printable(state)
        {:appliance, {:up_config_validate_result, line}, state}

      :down_config_commit ->
        {generation, state} = number(state)
        {deadline, state} = :rand.uniform_s(0xFFFF, state)
        {:server, {:down_config_commit, generation, deadline - 1}, state}

      :down_commit_confirm ->
        {generation, state} = number(state)
        {:server, {:down_commit_confirm, generation}, state}

      :down_range_read ->
        {ring, state} = ring(state)
        {start, state} = number(state)
        {length, state} = number(state)
        {:server, {:down_range_read, ring, start, length}, state}

      :up_range_data ->
        {ring, state} = ring(state)
        {position, state} = number(state)
        {which, state} = :rand.uniform_s(3, state)
        status = Enum.at([:data, :overwritten, :medium_refused], which - 1)

        {bytes, state} =
          if Frame.ends_the_answer?(status), do: {<<>>, state}, else: blob(state)

        {:appliance, {:up_range_data, ring, status, position, bytes}, state}
    end
  end

  # Drawn across the whole width of the field, and the extremes deliberately:
  # a cursor at nought and one at the top of a u64 are both values the wire
  # carries, and an off-by-one in the encoding shows up at the ends.
  defp number(state) do
    {which, state} = :rand.uniform_s(4, state)

    case which do
      1 -> {0, state}
      2 -> {@max_u64, state}
      3 -> {1, state}
      4 -> :rand.uniform_s(@max_u64, state)
    end
  end

  defp blob(state) do
    {length, state} = :rand.uniform_s(64, state)
    {bytes, state} = :rand.bytes_s(length - 1, state)
    {bytes, state}
  end

  defp printable(state) do
    {length, state} = :rand.uniform_s(48, state)

    Enum.map_reduce(1..length, state, fn _index, state ->
      {byte, state} = :rand.uniform_s(0x7E - 0x20 + 1, state)
      {byte + 0x1F, state}
    end)
    |> then(fn {bytes, state} -> {:binary.list_to_bin(bytes), state} end)
  end

  defp ring(state) do
    {which, state} = :rand.uniform_s(2, state)
    {Enum.at([:log, :capture], which - 1), state}
  end
end
