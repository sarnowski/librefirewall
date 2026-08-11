defmodule Ctrld.Channel.DecoderTest do
  @moduledoc """
  The incremental decoder against a stream cut in every place it can be cut.

  A frame arrives in whatever pieces the record layer under it produces, and the
  peer chooses those pieces. So the interesting input is not one stream but every
  segmentation of one, which is what the split-point tests enumerate: the same
  bytes must yield the same frames however they arrive, and a decoder that ever
  took a byte belonging to the next frame would disagree with itself between two
  splits.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Channel.{Decoder, Frame}

  defp encode(frame) do
    {:ok, iodata} = Frame.encode(:appliance, frame)
    IO.iodata_to_binary(iodata)
  end

  defp stream(frames), do: frames |> Enum.map(&encode/1) |> Enum.join()

  # The same as feeding, named for what the assertions around it are about.
  defp refuse(segments), do: feed(segments)

  # Every way a binary can be delivered in two pieces, the empty prefix and the
  # whole thing included.
  defp two_way_splits(bytes), do: for(at <- 0..byte_size(bytes), do: split_at(bytes, at))

  defp split_at(bytes, at) do
    <<head::binary-size(at), tail::binary>> = bytes
    [head, tail]
  end

  # Feed a decoder a list of segments in order, collecting what came out.
  defp feed(segments), do: feed(Decoder.new(:appliance), segments, [])

  defp feed(decoder, [], collected), do: {:ok, collected, decoder}

  defp feed(decoder, [segment | rest], collected) do
    case Decoder.absorb(decoder, segment) do
      {:ok, frames, decoder} -> feed(decoder, rest, collected ++ frames)
      {:refused, refusal, frames, decoder} -> {:refused, refusal, collected ++ frames, decoder}
    end
  end

  @greeting {:hello, :appliance}
  @records {:up_records, 42, "the log ring's own bytes"}
  @capture {:up_capture, 7, "the capture ring's own bytes"}
  @empty {:up_records, 0, <<>>}

  describe "one frame" do
    test "arrives whole" do
      assert {:ok, [@greeting], decoder} = feed([encode(@greeting)])
      assert Decoder.greeted?(decoder)
      assert Decoder.held(decoder) == 0
      assert Decoder.refusal(decoder) == nil
    end

    test "arrives in two pieces, cut at every possible point" do
      bytes = encode(@records)
      greeting = encode(@greeting)

      for [head, tail] <- two_way_splits(bytes) do
        assert {:ok, [@greeting, @records], _decoder} = feed([greeting, head, tail]),
               "a split after #{byte_size(head)} byte(s) did not yield both frames"
      end
    end

    test "arrives one byte at a time" do
      bytes = encode(@greeting) <> encode(@records)
      segments = for <<byte <- bytes>>, do: <<byte>>

      assert {:ok, [@greeting, @records], decoder} = feed(segments)
      assert Decoder.held(decoder) == 0
    end

    test "is not yielded before its last byte arrives" do
      bytes = encode(@greeting)
      short = binary_part(bytes, 0, byte_size(bytes) - 1)

      assert {:ok, [], decoder} = feed([short])
      refute Decoder.greeted?(decoder)
      assert Decoder.held(decoder) == byte_size(short)

      assert {:ok, [@greeting], decoder} =
               Decoder.absorb(decoder, binary_part(bytes, byte_size(bytes) - 1, 1))

      assert Decoder.held(decoder) == 0
    end

    test "a frame with an empty payload is a frame" do
      assert {:ok, [@greeting, @empty], _decoder} = feed([stream([@greeting, @empty])])
    end
  end

  describe "many frames" do
    test "in one segment, in order" do
      frames = [@greeting, @records, @capture, @empty]
      assert {:ok, ^frames, decoder} = feed([stream(frames)])
      assert Decoder.held(decoder) == 0
    end

    test "cut at every possible point, always the same frames in the same order" do
      frames = [@greeting, @records, @capture, @empty]
      bytes = stream(frames)

      for [head, tail] <- two_way_splits(bytes) do
        assert {:ok, ^frames, decoder} = feed([head, tail]),
               "a split after #{byte_size(head)} byte(s) changed what came out"

        assert Decoder.held(decoder) == 0
      end
    end

    test "cut at every pair of points, always the same frames" do
      frames = [@greeting, @records, @capture]
      bytes = stream(frames)
      size = byte_size(bytes)

      for first <- 0..size, second <- first..size do
        <<head::binary-size(first), middle::binary-size(second - first), tail::binary>> = bytes

        assert {:ok, ^frames, _decoder} = feed([head, middle, tail]),
               "splits after #{first} and #{second} byte(s) changed what came out"
      end
    end

    test "never takes a byte belonging to the next frame" do
      # A greeting whole, then one byte of the frame after it. What is held must
      # be that one byte and nothing else — if the decoder had taken the
      # greeting's bytes into a shared buffer and left them there, this would be
      # larger.
      <<first, _rest::binary>> = encode(@records)

      assert {:ok, [@greeting], decoder} = feed([encode(@greeting) <> <<first>>])
      assert Decoder.held(decoder) == 1
    end
  end

  describe "what is held is bounded" do
    test "a header stating a length past the bound is refused before its payload is taken" do
      header = <<1_048_577::unsigned-big-integer-32, 0x02, 0, 0, 0>>

      assert {:ok, [@greeting], decoder} = feed([encode(@greeting)])

      assert {:refused, {:payload_too_long, 1_048_577}, [], decoder} =
               Decoder.absorb(decoder, header <> :binary.copy(<<0>>, 4_096))

      # The eight bytes of the header, and not one byte of what followed it.
      assert Decoder.held(decoder) == 8
    end

    test "an unknown type byte is refused before its payload is taken" do
      header = <<1_024::unsigned-big-integer-32, 0xFF, 0, 0, 0>>

      assert {:ok, [@greeting], decoder} = feed([encode(@greeting)])

      assert {:refused, {:unknown_type, 0xFF}, [], decoder} =
               Decoder.absorb(decoder, header <> :binary.copy(<<0>>, 1_024))

      assert Decoder.held(decoder) == 8
    end

    test "a frame from the wrong end is refused before its payload is taken" do
      header = <<16::unsigned-big-integer-32, 0x04, 0, 0, 0>>

      assert {:ok, [@greeting], decoder} = feed([encode(@greeting)])

      assert {:refused, {:wrong_direction, :ack, :appliance}, [], decoder} =
               Decoder.absorb(decoder, header <> <<0::64, 0::64>>)

      assert Decoder.held(decoder) == 8
    end

    test "a staged document past its own bound is refused before its payload is taken" do
      # From the server's side, which is the end that may send one.
      decoder = Decoder.new(:server)
      {:ok, greeting} = Frame.encode(:server, {:hello, {:server, 0, 0}})
      assert {:ok, [_greeting], decoder} = Decoder.absorb(decoder, IO.iodata_to_binary(greeting))

      header = <<65_537::unsigned-big-integer-32, 0x05, 0, 0, 0>>

      assert {:refused, {:config_document_too_long, 65_537}, [], decoder} =
               Decoder.absorb(decoder, header <> :binary.copy(<<0x20>>, 65_537))

      assert Decoder.held(decoder) == 8
    end

    test "a frame at the payload bound is held and yielded" do
      payload = :binary.copy(<<0>>, Frame.max_payload_length() - 8)
      frames = [@greeting, {:up_records, 1, payload}]
      bytes = stream(frames)

      assert byte_size(bytes) == byte_size(encode(@greeting)) + 8 + Frame.max_payload_length()

      # In segments a record layer might plausibly produce, so the reassembly is
      # exercised rather than handed the whole frame at once.
      segments = for <<segment::binary-size(16_384) <- bytes>>, do: segment

      tail =
        binary_part(
          bytes,
          length(segments) * 16_384,
          byte_size(bytes) - length(segments) * 16_384
        )

      assert {:ok, ^frames, decoder} = feed(segments ++ [tail])
      assert Decoder.held(decoder) == 0
    end
  end

  describe "refusing, by name" do
    test "first_frame_not_hello" do
      assert {:refused, {:first_frame_not_hello, :up_records}, [], _decoder} =
               refuse([encode(@records)])
    end

    test "reserved_non_zero, naming which byte" do
      assert {:refused, {:reserved_non_zero, 0, 1}, [], _decoder} =
               refuse([<<0::32, 0x01, 1, 0, 0>>])

      assert {:refused, {:reserved_non_zero, 1, 9}, [], _decoder} =
               refuse([<<0::32, 0x01, 0, 9, 0>>])

      assert {:refused, {:reserved_non_zero, 2, 255}, [], _decoder} =
               refuse([<<0::32, 0x01, 0, 0, 255>>])
    end

    test "unknown_type" do
      assert {:refused, {:unknown_type, 0}, [], _decoder} = refuse([<<0::32, 0, 0, 0, 0>>])
      assert {:refused, {:unknown_type, 11}, [], _decoder} = refuse([<<0::32, 11, 0, 0, 0>>])
    end

    test "payload_too_long" do
      assert {:refused, {:payload_too_long, 1_048_577}, [], _decoder} =
               refuse([<<1_048_577::32, 0x01, 0, 0, 0>>])
    end

    test "wrong_direction" do
      assert {:refused, {:wrong_direction, :down_range_read, :appliance}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<17::32, 0x09, 0, 0, 0>>])
    end

    test "version_mismatch" do
      assert {:refused, {:version_mismatch, 2}, [], _decoder} =
               refuse([<<2::32, 0x01, 0, 0, 0, 2::16>>])
    end

    test "payload_length" do
      assert {:refused, {:payload_length, :hello, 3, 2}, [], _decoder} =
               refuse([<<3::32, 0x01, 0, 0, 0, 1::16, 0>>])
    end

    test "unknown_ring" do
      assert {:refused, {:unknown_ring, 2}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<10::32, 0x0A, 0, 0, 0, 2, 0, 0::64>>])

      # Ahead of the payload's own length, exactly as the appliance's codec reads
      # it: a selector naming neither recording is a more useful answer than the
      # length of a payload that also happens to be short.
      assert {:refused, {:unknown_ring, 2}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<1::32, 0x0A, 0, 0, 0, 2>>])
    end

    test "unknown_range_status" do
      assert {:refused, {:unknown_range_status, 7}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<10::32, 0x0A, 0, 0, 0, 0, 7, 0::64>>])

      # And ahead of the length here too, for the same reason.
      assert {:refused, {:unknown_range_status, 7}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<2::32, 0x0A, 0, 0, 0, 0, 7>>])
    end

    test "bytes_on_ended_range" do
      assert {:refused, {:bytes_on_ended_range, :overwritten, 1}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<11::32, 0x0A, 0, 0, 0, 0, 1, 0::64, "x">>])
    end

    test "result_line_not_printable" do
      assert {:refused, {:result_line_not_printable, 2, 10}, [@greeting], _decoder} =
               refuse([encode(@greeting), <<3::32, 0x06, 0, 0, 0, "ok\n">>])
    end
  end

  describe "a violation is terminal" do
    test "frames that completed before it come back beside it" do
      bytes = stream([@greeting, @records]) <> <<0::32, 0xFF, 0, 0, 0>>

      assert {:refused, {:unknown_type, 0xFF}, [@greeting, @records], _decoder} = feed([bytes])
    end

    test "nothing is read from the peer afterwards" do
      assert {:refused, refusal, [], decoder} = feed([<<0::32, 0xFF, 0, 0, 0>>])
      assert Decoder.refusal(decoder) == refusal

      # A whole valid greeting after the violation yields nothing: a stream whose
      # framing is wrong has no next frame to find.
      assert {:refused, ^refusal, [], _decoder} = Decoder.absorb(decoder, encode(@greeting))
    end

    test "the bytes that followed it are neither taken nor interpreted" do
      # A refused header, then a whole greeting and half a second frame behind it,
      # all in one arrival. The refusing header is held and not one byte more, so
      # what followed it was never taken — and none of it is interpreted, the
      # greeting in there included.
      trailing = encode(@greeting) <> binary_part(encode(@records), 0, 12)

      assert {:refused, {:unknown_type, 0xFF}, [], decoder} =
               feed([<<0::32, 0xFF, 0, 0, 0>> <> trailing])

      assert Decoder.held(decoder) == Frame.header_length()
      assert {:refused, {:unknown_type, 0xFF}, [], spent} = Decoder.absorb(decoder, trailing)
      assert Decoder.held(spent) == Frame.header_length()
    end

    test "a frame refused on its payload had been held, and nothing behind it" do
      # The header was admissible, so the whole frame was taken before its payload
      # could be judged — and the whole frame is the bound: the greeting sent
      # behind it in the same arrival is not held and not decoded.
      refused = <<3::32, 0x06, 0, 0, 0, "ok\n">>

      assert {:refused, {:result_line_not_printable, 2, 10}, [@greeting], decoder} =
               feed([encode(@greeting) <> refused <> encode(@records)])

      assert Decoder.held(decoder) == byte_size(refused)
    end

    test "the same violation is answered however the bytes were cut" do
      bytes = stream([@greeting]) <> <<0::32, 0xFF, 0, 0, 0>>

      for [head, tail] <- two_way_splits(bytes) do
        assert {:refused, {:unknown_type, 0xFF}, [@greeting], _decoder} = feed([head, tail]),
               "a split after #{byte_size(head)} byte(s) changed the refusal"
      end
    end
  end

  describe "the other direction" do
    test "the server's greeting decodes with its cursors" do
      decoder = Decoder.new(:server)
      {:ok, bytes} = Frame.encode(:server, {:hello, {:server, 11, 22}})

      assert {:ok, [{:hello, {:server, 11, 22}}], _decoder} =
               Decoder.absorb(decoder, IO.iodata_to_binary(bytes))
    end

    test "an appliance frame from the server is refused" do
      decoder = Decoder.new(:server)
      {:ok, greeting} = Frame.encode(:server, {:hello, {:server, 0, 0}})
      {:ok, decoder} = drain(Decoder.absorb(decoder, IO.iodata_to_binary(greeting)))

      assert {:refused, {:wrong_direction, :up_records, :server}, [], _decoder} =
               Decoder.absorb(decoder, <<8::32, 0x02, 0, 0, 0, 0::64>>)
    end
  end

  defp drain({:ok, _frames, decoder}), do: {:ok, decoder}
end
