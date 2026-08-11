defmodule Ctrld.Channel.Decoder do
  @moduledoc """
  The peer's byte stream, one frame at a time.

  A frame carries up to a mebibyte and arrives in as many pieces as the record
  layer under it produces, so reassembly happens here: `absorb/2` takes whatever
  a segment brought, hands back every frame that completed, and keeps only the
  part of one frame that has not arrived yet.

  ## Adversary

  A **semi-trusted appliance, up to and including a compromised one**. The peer
  chooses the lengths, the type bytes, and how a frame is cut across arrivals —
  and it chooses the pacing, which is the lever this module has to close.

  Two properties do the closing, and both are about what is *held*:

    * **One frame's worth, and never two.** No byte past the end of the frame
      being assembled is ever taken into the buffer. The rest stays where it
      arrived, so the buffer holds a prefix of exactly one frame at every
      instant, and a completed frame leaves it empty rather than being copied
      down it.

    * **Nothing behind a header this end will refuse is ever taken.** The bytes
      still wanted are read from the header through the same check that decides
      what a frame *is*, so a header stating a length past the bound — or naming
      an unknown type, or a frame from the wrong end — costs eight bytes rather
      than a mebibyte of buffering. A peer cannot make this end hold anything on
      the strength of a number it has already decided to refuse.

  A violation is terminal: the decoder answers that violation and nothing else
  from there on, because a stream whose framing is wrong has no next frame —
  where the following header starts is exactly what has been lost. Nothing here
  closes a connection or counts anything; both belong to the session above.
  """

  alias Ctrld.Channel.Frame

  @header_length Frame.header_length()

  @enforce_keys [:sender]
  defstruct [:sender, :refusal, buffer: <<>>, greeted?: false]

  @typedoc """
  A decoder for one direction of one connection.

  `sender` is which end's frames these are, and it is fixed for the decoder's
  life: a connection has two ends and neither becomes the other.
  """
  @type t :: %__MODULE__{
          sender: Frame.side(),
          refusal: Frame.refusal() | nil,
          buffer: binary(),
          greeted?: boolean()
        }

  @doc "A decoder for the frames `sender` sends: on this server, `:appliance`."
  @spec new(Frame.side()) :: t()
  def new(sender) when sender in [:appliance, :server], do: %__MODULE__{sender: sender}

  @doc "The rule the peer broke, once it has broken one."
  @spec refusal(t()) :: Frame.refusal() | nil
  def refusal(%__MODULE__{refusal: refusal}), do: refusal

  @doc "Whether a greeting has been decoded in this direction."
  @spec greeted?(t()) :: boolean()
  def greeted?(%__MODULE__{greeted?: greeted?}), do: greeted?

  @doc """
  Bytes of a frame currently held, which is at most one frame's worth.

  Exposed so the property that bounds this module is one a test can assert
  rather than one a comment claims.
  """
  @spec held(t()) :: non_neg_integer()
  def held(%__MODULE__{buffer: buffer}), do: byte_size(buffer)

  @doc """
  Take `bytes` and answer every frame that completed, in arrival order.

  On a violation the frames that completed *before* it come back beside it: each
  was a whole, well-formed frame of this protocol before the peer broke it, and
  discarding them would make what a session received depend on where the record
  layer happened to cut the stream — the same bytes yielding different frames per
  segmentation, which is the one thing this module exists to rule out.

  Nothing after the violation is interpreted, ever. The bytes that arrived behind
  the refused frame are not taken, and the decoder is spent: a further `absorb/2`
  answers the same violation with no frames, whatever it is handed. So a caller
  takes the frames, then closes — which is the only thing left to do.
  """
  @spec absorb(t(), binary()) ::
          {:ok, [Frame.t()], t()} | {:refused, Frame.refusal(), [Frame.t()], t()}
  def absorb(%__MODULE__{refusal: refusal} = decoder, bytes)
      when not is_nil(refusal) and is_binary(bytes) do
    {:refused, refusal, [], decoder}
  end

  def absorb(%__MODULE__{} = decoder, bytes) when is_binary(bytes) do
    run(decoder, bytes, [])
  end

  # One pass per look at the frame in progress. Each either finds it whole and
  # emits it, takes exactly the bytes it still wants out of what arrived, or runs
  # out of arrived bytes and stops. `rest` is a sub-binary of what the caller
  # handed over, so what has not been taken costs a reference and not a copy.
  #
  # It terminates because every pass that does not stop either empties the buffer
  # by emitting a frame or moves at least one byte out of `rest` — a frame is
  # never whole with fewer bytes than its header, so a pass following an emitted
  # frame must take from `rest` or stop.
  defp run(decoder, rest, emitted) do
    case wanted(decoder) do
      {:error, refusal} ->
        refused(decoder, refusal, emitted)

      {:ok, wanted} ->
        held = byte_size(decoder.buffer)

        cond do
          wanted == held -> emit(decoder, rest, emitted)
          byte_size(rest) < wanted - held -> {:ok, Enum.reverse(emitted), buffered(decoder, rest)}
          true -> take(decoder, rest, wanted - held, emitted)
        end
    end
  end

  # Every arrived byte belongs to the frame in progress, so all of them are held
  # and the caller is answered with what completed before them.
  defp buffered(decoder, rest), do: %{decoder | buffer: decoder.buffer <> rest}

  # The single place bytes cross from an arrival into the buffer, and it takes
  # `wanted - held` of them and not one more. That subtraction is what makes "one
  # frame's worth and never two" a property of this line rather than of the
  # reasoning around it.
  defp take(decoder, rest, needed, emitted) do
    <<taken::binary-size(needed), remaining::binary>> = rest
    run(%{decoder | buffer: decoder.buffer <> taken}, remaining, emitted)
  end

  defp emit(%__MODULE__{buffer: buffer} = decoder, rest, emitted) do
    <<header::binary-size(@header_length), payload::binary>> = buffer

    with {:ok, type, _length} <- Frame.read_header(header, decoder.sender, decoder.greeted?),
         {:ok, frame} <- Frame.read_payload(type, decoder.sender, payload) do
      run(%{decoder | buffer: <<>>, greeted?: true}, rest, [frame | emitted])
    else
      {:error, refusal} -> refused(decoder, refusal, emitted)
    end
  end

  # The buffer is left as it stands, which is the refused frame and nothing behind
  # it. Emptying it here would cost nothing on a connection that is about to close
  # and would take away the only observable the bound above has: what `held/1`
  # answers after a refusal is how much of the peer's stream this end took before
  # refusing it, and a header refused for eight bytes is exactly the property that
  # a length, a type byte or a direction cannot make this end buffer a mebibyte.
  defp refused(decoder, refusal, emitted) do
    {:refused, refusal, Enum.reverse(emitted), %{decoder | refusal: refusal}}
  end

  # Bytes the frame in progress needs before it is whole: a header's worth until
  # there is a header, then what the header states. A header this end refuses
  # answers the refusal instead, which is what keeps the payload behind it
  # untaken.
  defp wanted(%__MODULE__{buffer: buffer}) when byte_size(buffer) < @header_length do
    {:ok, @header_length}
  end

  defp wanted(%__MODULE__{buffer: buffer} = decoder) do
    <<header::binary-size(@header_length), _payload::binary>> = buffer

    case Frame.read_header(header, decoder.sender, decoder.greeted?) do
      {:ok, _type, length} -> {:ok, @header_length + length}
      {:error, refusal} -> {:error, refusal}
    end
  end
end
