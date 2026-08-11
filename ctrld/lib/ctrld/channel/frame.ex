defmodule Ctrld.Channel.Frame do
  @moduledoc """
  The management channel's wire vocabulary, and the codec for one frame.

  The ten frames that cross the one persistent connection an appliance dials,
  in both directions, as this server writes and reads them. It is the server's
  half of a protocol whose other half ships from the same project in Rust, so
  every number here is the wire's and not a choice made twice: the eight-byte
  header, the mebibyte payload bound, the type bytes, the direction each frame
  may travel, and the two closed byte vocabularies inside the payloads.

  ## Adversary

  A **semi-trusted appliance, up to and including a compromised one**. Every
  byte `read_header/3` and `read_payload/3` see was chosen by the peer — the
  lengths, the type bytes, the reserved bytes, the ring selectors, the version.
  That the session below authenticated the peer is not a reason to model it as
  well-behaved: a compromised appliance holds a certificate this server itself
  issued, and what bounds it is the arithmetic here.

  So a peer's bytes never reach a call that could raise. Every field is read by
  matching a binary of a known size, so a payload that runs out mid-field is a
  refusal and not an exception; no length a peer states is believed before it is
  compared against a constant of this module; and no byte a peer sent becomes an
  atom.

  ## One refusal per rule broken

  `t:refusal/0` has one value per cause and none standing for several, because a
  refusal is what an operator is left with after the connection closed. A header
  of a protocol this is not, a frame the peer's own end may not send, a document
  past its own bound and a range answer that contradicts itself are four
  different things to go and look at.

  Nothing here logs, counts, or closes anything: a refusal is a returned value,
  and what to do about it belongs to the session above.
  """

  @header_length 8
  @max_payload_length 1_048_576
  @max_document_length 65_536
  @version 1
  @appliance_hello_length 2
  @server_hello_length 18

  @first_printable 0x20
  @last_printable 0x7E

  @typedoc "Which end of the channel sent, or is about to send, a frame."
  @type side :: :appliance | :server

  @typedoc "Which recording ring a position, a request or an answer is about."
  @type ring :: :log | :capture

  @typedoc "How a range answer went: bytes, or the reason there are none."
  @type range_status :: :data | :overwritten | :medium_refused

  @typedoc "The ten frames, by the name the contract gives each."
  @type frame_type ::
          :hello
          | :up_records
          | :up_capture
          | :ack
          | :down_config_stage
          | :up_config_validate_result
          | :down_config_commit
          | :down_commit_confirm
          | :down_range_read
          | :up_range_data

  @typedoc """
  A greeting's payload, decoded.

  The version is not in it, and its absence is the point: a greeting naming a
  version this end does not speak never becomes a value at all, it becomes
  `{:version_mismatch, theirs}`. So a greeting in hand is one in the single
  version this protocol has, and no caller has to check.
  """
  @type hello :: :appliance | {:server, log :: non_neg_integer(), capture :: non_neg_integer()}

  @typedoc "One frame, decoded — or one to encode."
  @type t ::
          {:hello, hello()}
          | {:up_records, position :: non_neg_integer(), bytes :: binary()}
          | {:up_capture, position :: non_neg_integer(), bytes :: binary()}
          | {:ack, log :: non_neg_integer(), capture :: non_neg_integer()}
          | {:down_config_stage, document :: binary()}
          | {:up_config_validate_result, line :: binary()}
          | {:down_config_commit, generation :: non_neg_integer(),
             confirm_deadline_secs :: non_neg_integer()}
          | {:down_commit_confirm, generation :: non_neg_integer()}
          | {:down_range_read, ring(), start :: non_neg_integer(), length :: non_neg_integer()}
          | {:up_range_data, ring(), range_status(), position :: non_neg_integer(),
             bytes :: binary()}

  @typedoc """
  Why a peer's bytes are not a frame of this protocol.

  A violation closes the connection and nothing else happens — there is no
  recovery and no resynchronisation, because a stream whose framing is wrong has
  no next frame: where the following header starts is exactly what has been
  lost.
  """
  @type refusal ::
          {:reserved_non_zero, at :: 0..2, byte :: byte()}
          | {:unknown_type, byte :: byte()}
          | {:payload_too_long, stated :: non_neg_integer()}
          | {:wrong_direction, frame_type(), side()}
          | {:first_frame_not_hello, frame_type()}
          | {:version_mismatch, theirs :: non_neg_integer()}
          | {:payload_length, frame_type(), len :: non_neg_integer(), needed :: non_neg_integer()}
          | {:unknown_ring, byte :: byte()}
          | {:unknown_range_status, byte :: byte()}
          | {:bytes_on_ended_range, range_status(), len :: non_neg_integer()}
          | {:config_document_too_long, len :: non_neg_integer()}
          | {:result_line_not_printable, at :: non_neg_integer(), byte :: byte()}

  @typedoc """
  Why a frame this end composed was not written.

  Every one is a defect above this module rather than a peer's doing, which is
  what separates this vocabulary from `t:refusal/0`. Each has the decoding
  refusal it would have produced at the far end, so a frame refused here is
  exactly a frame the appliance would have closed the connection over.
  """
  @type encode_refusal ::
          {:wrong_direction, frame_type(), side()}
          | {:payload_too_long, len :: non_neg_integer()}
          | {:config_document_too_long, len :: non_neg_integer()}
          | :empty_result_line
          | {:result_line_not_printable, at :: non_neg_integer(), byte :: byte()}
          | {:bytes_on_ended_range, range_status(), len :: non_neg_integer()}

  @doc "Bytes of header in front of every frame's payload."
  @spec header_length() :: pos_integer()
  def header_length, do: @header_length

  @doc "Bytes of payload one frame may carry, matching a recording segment."
  @spec max_payload_length() :: pos_integer()
  def max_payload_length, do: @max_payload_length

  @doc "Bytes a staged configuration document may be — its own bound, far below the frame's."
  @spec max_document_length() :: pos_integer()
  def max_document_length, do: @max_document_length

  @doc "The protocol version this end speaks, and the only one it does."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc "Every frame this protocol has, in the order the type byte numbers them."
  @spec all_types() :: [frame_type()]
  def all_types do
    [
      :hello,
      :up_records,
      :up_capture,
      :ack,
      :down_config_stage,
      :up_config_validate_result,
      :down_config_commit,
      :down_commit_confirm,
      :down_range_read,
      :up_range_data
    ]
  end

  @doc "The type byte that names a frame."
  @spec type_byte(frame_type()) :: byte()
  def type_byte(:hello), do: 0x01
  def type_byte(:up_records), do: 0x02
  def type_byte(:up_capture), do: 0x03
  def type_byte(:ack), do: 0x04
  def type_byte(:down_config_stage), do: 0x05
  def type_byte(:up_config_validate_result), do: 0x06
  def type_byte(:down_config_commit), do: 0x07
  def type_byte(:down_commit_confirm), do: 0x08
  def type_byte(:down_range_read), do: 0x09
  def type_byte(:up_range_data), do: 0x0A

  @doc """
  The frame a type byte names, or nothing.

  There is no frame numbered zero, so a run of zeroed bytes is a violation
  rather than a greeting.
  """
  @spec type_from_byte(byte()) :: {:ok, frame_type()} | :error
  def type_from_byte(0x01), do: {:ok, :hello}
  def type_from_byte(0x02), do: {:ok, :up_records}
  def type_from_byte(0x03), do: {:ok, :up_capture}
  def type_from_byte(0x04), do: {:ok, :ack}
  def type_from_byte(0x05), do: {:ok, :down_config_stage}
  def type_from_byte(0x06), do: {:ok, :up_config_validate_result}
  def type_from_byte(0x07), do: {:ok, :down_config_commit}
  def type_from_byte(0x08), do: {:ok, :down_commit_confirm}
  def type_from_byte(0x09), do: {:ok, :down_range_read}
  def type_from_byte(0x0A), do: {:ok, :up_range_data}
  def type_from_byte(byte) when is_integer(byte) and byte in 0..255, do: :error

  @doc """
  Whether `side` is an end a frame may travel from.

  The greeting travels both ways; every other frame travels one way only, and
  that is what makes a great deal of this protocol safe by construction. A
  server acting on an acknowledgement it received is not a shape the wire can
  express, and a peer probing which frames this end will dispatch on without
  checking who sent them is refused rather than answered.
  """
  @spec may_travel_from?(frame_type(), side()) :: boolean()
  def may_travel_from?(:hello, side) when side in [:appliance, :server], do: true

  def may_travel_from?(type, :appliance)
      when type in [:up_records, :up_capture, :up_config_validate_result, :up_range_data],
      do: true

  def may_travel_from?(type, :server)
      when type in [
             :ack,
             :down_config_stage,
             :down_config_commit,
             :down_commit_confirm,
             :down_range_read
           ],
      do: true

  def may_travel_from?(type, side) when is_atom(type) and side in [:appliance, :server], do: false

  @doc """
  Bytes of payload a frame needs before any variable part of it.

  For a frame with no variable part this is the payload's exact length. One
  number for both readings, because it is only ever reported: it is the `needed`
  a `{:payload_length, ...}` refusal carries beside the length the peer actually
  sent. What decides the shape is the reader that walks the fields, which runs
  out of bytes on a short payload and finds bytes left over on a long one.
  """
  @spec payload_floor(frame_type(), side()) :: non_neg_integer()
  def payload_floor(:hello, :appliance), do: @appliance_hello_length
  def payload_floor(:hello, :server), do: @server_hello_length
  def payload_floor(:up_records, side) when side in [:appliance, :server], do: 8
  def payload_floor(:up_capture, side) when side in [:appliance, :server], do: 8
  def payload_floor(:ack, side) when side in [:appliance, :server], do: 16
  def payload_floor(:down_config_stage, side) when side in [:appliance, :server], do: 0
  def payload_floor(:up_config_validate_result, side) when side in [:appliance, :server], do: 1
  def payload_floor(:down_config_commit, side) when side in [:appliance, :server], do: 10
  def payload_floor(:down_commit_confirm, side) when side in [:appliance, :server], do: 8
  def payload_floor(:down_range_read, side) when side in [:appliance, :server], do: 17
  def payload_floor(:up_range_data, side) when side in [:appliance, :server], do: 10

  @doc "Which frame a decoded value is."
  @spec frame_type(t()) :: frame_type()
  def frame_type(frame) when is_tuple(frame), do: elem(frame, 0)

  @doc "The end a greeting of this shape comes from."
  @spec hello_side(hello()) :: side()
  def hello_side(:appliance), do: :appliance
  def hello_side({:server, _log, _capture}), do: :server

  @doc "The byte that selects a recording ring."
  @spec ring_byte(ring()) :: byte()
  def ring_byte(:log), do: 0
  def ring_byte(:capture), do: 1

  @doc "The ring a selector byte names, or nothing."
  @spec ring_from_byte(byte()) :: {:ok, ring()} | :error
  def ring_from_byte(0), do: {:ok, :log}
  def ring_from_byte(1), do: {:ok, :capture}
  def ring_from_byte(byte) when is_integer(byte) and byte in 0..255, do: :error

  @doc "The byte that carries a range answer's status."
  @spec range_status_byte(range_status()) :: byte()
  def range_status_byte(:data), do: 0
  def range_status_byte(:overwritten), do: 1
  def range_status_byte(:medium_refused), do: 2

  @doc "The status a byte names, or nothing."
  @spec range_status_from_byte(byte()) :: {:ok, range_status()} | :error
  def range_status_from_byte(0), do: {:ok, :data}
  def range_status_from_byte(1), do: {:ok, :overwritten}
  def range_status_from_byte(2), do: {:ok, :medium_refused}
  def range_status_from_byte(byte) when is_integer(byte) and byte in 0..255, do: :error

  @doc """
  Whether a status ends the answer, and so may carry no bytes.

  The two failures end it because the recording discipline says so: a reader
  that cannot serve an extent says so rather than returning a short one, since a
  truncated answer and a complete one would be indistinguishable to whoever
  ingests it.
  """
  @spec ends_the_answer?(range_status()) :: boolean()
  def ends_the_answer?(:data), do: false
  def ends_the_answer?(status) when status in [:overwritten, :medium_refused], do: true

  @doc """
  Write `frame` as `sender`, header and payload, as iodata.

  Iodata rather than a binary because the two upstream frames carry up to a
  mebibyte of a recording's own bytes: the ring bytes are the wire bytes, and
  copying them to prepend eight would move a megabyte for nothing.
  """
  @spec encode(side(), t()) :: {:ok, iodata()} | {:error, encode_refusal()}
  def encode(sender, frame) when sender in [:appliance, :server] and is_tuple(frame) do
    with :ok <- writable(sender, frame),
         {:ok, payload} <- payload(frame) do
      length = IO.iodata_length(payload)

      if length > @max_payload_length do
        {:error, {:payload_too_long, length}}
      else
        header = <<length::unsigned-big-integer-32, type_byte(frame_type(frame)), 0, 0, 0>>
        {:ok, [header, payload]}
      end
    end
  end

  # Direction first, because it is the question about the frame rather than
  # about its contents — and for a greeting it is also the question of which of
  # the two shapes this end has any business sending: an appliance cannot send
  # the server's greeting, carrying resume cursors it has no business holding.
  defp writable(sender, {:hello, hello}) do
    if hello_side(hello) == sender, do: :ok, else: {:error, {:wrong_direction, :hello, sender}}
  end

  defp writable(sender, frame) do
    type = frame_type(frame)
    if may_travel_from?(type, sender), do: :ok, else: {:error, {:wrong_direction, type, sender}}
  end

  defp payload({:hello, :appliance}), do: {:ok, <<@version::unsigned-big-integer-16>>}

  defp payload({:hello, {:server, log, capture}}) do
    {:ok,
     <<@version::unsigned-big-integer-16, log::unsigned-big-integer-64,
       capture::unsigned-big-integer-64>>}
  end

  defp payload({:up_records, position, bytes}) when is_binary(bytes) do
    {:ok, [<<position::unsigned-big-integer-64>>, bytes]}
  end

  defp payload({:up_capture, position, bytes}) when is_binary(bytes) do
    {:ok, [<<position::unsigned-big-integer-64>>, bytes]}
  end

  defp payload({:ack, log, capture}) do
    {:ok, <<log::unsigned-big-integer-64, capture::unsigned-big-integer-64>>}
  end

  defp payload({:down_config_stage, document})
       when is_binary(document) and byte_size(document) > @max_document_length do
    {:error, {:config_document_too_long, byte_size(document)}}
  end

  defp payload({:down_config_stage, document}) when is_binary(document), do: {:ok, document}

  # A result that says nothing is not a result, and the receiving end refuses
  # one, so this end does not compose one.
  defp payload({:up_config_validate_result, <<>>}), do: {:error, :empty_result_line}

  defp payload({:up_config_validate_result, line}) when is_binary(line) do
    case first_unprintable(line, 0) do
      nil -> {:ok, line}
      {at, byte} -> {:error, {:result_line_not_printable, at, byte}}
    end
  end

  defp payload({:down_config_commit, generation, confirm_deadline_secs}) do
    {:ok, <<generation::unsigned-big-integer-64, confirm_deadline_secs::unsigned-big-integer-16>>}
  end

  defp payload({:down_commit_confirm, generation}) do
    {:ok, <<generation::unsigned-big-integer-64>>}
  end

  defp payload({:down_range_read, ring, start, length}) do
    {:ok, <<ring_byte(ring), start::unsigned-big-integer-64, length::unsigned-big-integer-64>>}
  end

  defp payload({:up_range_data, ring, status, position, bytes}) when is_binary(bytes) do
    if ends_the_answer?(status) and bytes != <<>> do
      {:error, {:bytes_on_ended_range, status, byte_size(bytes)}}
    else
      head = <<ring_byte(ring), range_status_byte(status), position::unsigned-big-integer-64>>
      {:ok, [head, bytes]}
    end
  end

  @doc """
  What a complete header names: the frame and its payload's length.

  Read in the order the contract lists its violations. The order matters only
  where a header breaks several rules at once — each cause has a value of its
  own, so what the order decides is which of them an operator is sent after
  first.

  `greeted?` is whether a frame has already been decoded in this direction,
  which is the whole of what makes "the first frame is the greeting" a rule this
  end enforces.
  """
  @spec read_header(binary(), side(), boolean()) ::
          {:ok, frame_type(), non_neg_integer()} | {:error, refusal()}
  def read_header(
        <<stated::unsigned-big-integer-32, kind, reserved_0, reserved_1, reserved_2>>,
        sender,
        greeted?
      )
      when sender in [:appliance, :server] and is_boolean(greeted?) do
    with :ok <- reserved_zero(reserved_0, reserved_1, reserved_2),
         {:ok, type} <- known_type(kind),
         :ok <- within_bound(stated),
         :ok <- travels(type, sender),
         :ok <- greeting_first(type, greeted?) do
      document_within_bound(type, stated)
    end
  end

  # The reserved bytes first. They are the one part of a header that carries no
  # meaning to get wrong, so a nonzero one says the peer is not speaking this
  # protocol rather than speaking it badly — and that sends an operator
  # somewhere entirely different from every refusal below.
  defp reserved_zero(0, 0, 0), do: :ok
  defp reserved_zero(byte, _one, _two) when byte != 0, do: {:error, {:reserved_non_zero, 0, byte}}

  defp reserved_zero(_zero, byte, _two) when byte != 0,
    do: {:error, {:reserved_non_zero, 1, byte}}

  defp reserved_zero(_zero, _one, byte), do: {:error, {:reserved_non_zero, 2, byte}}

  defp known_type(kind) do
    case type_from_byte(kind) do
      {:ok, type} -> {:ok, type}
      :error -> {:error, {:unknown_type, kind}}
    end
  end

  defp within_bound(stated) when stated > @max_payload_length,
    do: {:error, {:payload_too_long, stated}}

  defp within_bound(_stated), do: :ok

  defp travels(type, sender) do
    if may_travel_from?(type, sender), do: :ok, else: {:error, {:wrong_direction, type, sender}}
  end

  defp greeting_first(:hello, _greeted?), do: :ok
  defp greeting_first(_type, true), do: :ok
  defp greeting_first(type, false), do: {:error, {:first_frame_not_hello, type}}

  # The one frame with a length bound of its own, and it is read off the header
  # for the same reason the frame bound is: a document past its bound is refused
  # before a byte of it is held, so a peer cannot make this end buffer a
  # mebibyte for a stage that would take a sixteenth of it.
  defp document_within_bound(:down_config_stage, stated) when stated > @max_document_length,
    do: {:error, {:config_document_too_long, stated}}

  defp document_within_bound(type, stated), do: {:ok, type, stated}

  @doc """
  One payload's fields, in order, or the rule its bytes broke.

  Every field is read by matching a binary of a known size, so a payload that
  runs out mid-field is `{:payload_length, ...}` and never an exception — and the
  same refusal covers trailing bytes on a frame with nothing variable in it,
  both being "the payload is not this frame's shape". The refusals with a cause
  of their own are raised where they are found, which is why the fields are read
  in order rather than checked up front: a selector byte that names no ring is a
  more useful answer than the length of a payload that also happens to be short.
  """
  @spec read_payload(frame_type(), side(), binary()) :: {:ok, t()} | {:error, refusal()}
  def read_payload(type, sender, payload)
      when is_atom(type) and sender in [:appliance, :server] and is_binary(payload) do
    fields(type, sender, payload)
  end

  defp fields(:hello, sender, <<version::unsigned-big-integer-16, rest::binary>> = payload) do
    # Before the rest of the shape is judged, and deliberately: a peer speaking
    # another version has another greeting shape too, so "your version is not
    # mine" is the answer that sends somebody to an update, where "your payload
    # is the wrong length" would send them looking for a corrupted frame.
    if version != @version do
      {:error, {:version_mismatch, version}}
    else
      greeting(sender, rest, byte_size(payload))
    end
  end

  defp fields(:up_records, _sender, <<position::unsigned-big-integer-64, bytes::binary>>) do
    {:ok, {:up_records, position, bytes}}
  end

  defp fields(:up_capture, _sender, <<position::unsigned-big-integer-64, bytes::binary>>) do
    {:ok, {:up_capture, position, bytes}}
  end

  defp fields(:ack, _sender, <<log::unsigned-big-integer-64, capture::unsigned-big-integer-64>>) do
    {:ok, {:ack, log, capture}}
  end

  # The document's own bound was read off the header, so what arrives here is a
  # document of an admissible length and every byte of it is the configuration
  # reader's to judge — including an empty one, which that reader refuses with an
  # offset a length here could not give.
  defp fields(:down_config_stage, _sender, payload), do: {:ok, {:down_config_stage, payload}}

  # The pattern is what refuses an empty line: a payload of no bytes falls
  # through to the shape refusal below, which is where "a result that says
  # nothing is not a result" is answered with the one byte it owed.
  defp fields(:up_config_validate_result, _sender, <<_first, _rest::binary>> = payload) do
    case first_unprintable(payload, 0) do
      nil -> {:ok, {:up_config_validate_result, payload}}
      {at, byte} -> {:error, {:result_line_not_printable, at, byte}}
    end
  end

  defp fields(
         :down_config_commit,
         _sender,
         <<generation::unsigned-big-integer-64, deadline::unsigned-big-integer-16>>
       ) do
    {:ok, {:down_config_commit, generation, deadline}}
  end

  defp fields(:down_commit_confirm, _sender, <<generation::unsigned-big-integer-64>>) do
    {:ok, {:down_commit_confirm, generation}}
  end

  # The two frames with a closed byte vocabulary in front of their numbers, and
  # the selector is read on its own so a byte naming no ring is answered as one
  # even on a payload that is also short. Which refusal a peer gets is the whole
  # value of having twelve of them: "a ring selector names neither recording"
  # sends an operator somewhere quite different from "the payload is not this
  # frame's shape", and the appliance's own codec walks the fields in this order
  # for the same reason.
  defp fields(:down_range_read, sender, <<selector, rest::binary>> = payload) do
    with {:ok, ring} <- selected_ring(selector),
         <<start::unsigned-big-integer-64, length::unsigned-big-integer-64>> <- rest do
      # The two numbers are carried and judged nowhere here: what a position
      # means is the ring's, and an extent past its head or behind its tail is
      # answered by the appliance, which has the geometry.
      {:ok, {:down_range_read, ring, start, length}}
    else
      {:error, refusal} -> {:error, refusal}
      _not_two_numbers -> shape(:down_range_read, sender, byte_size(payload))
    end
  end

  defp fields(:up_range_data, sender, <<selector, rest::binary>> = payload) do
    with {:ok, ring} <- selected_ring(selector),
         <<code, rest::binary>> <- rest,
         {:ok, status} <- selected_status(code),
         <<position::unsigned-big-integer-64, bytes::binary>> <- rest do
      if ends_the_answer?(status) and bytes != <<>> do
        # A frame contradicting itself, and the contradiction matters: an ingest
        # that believed the bytes would be writing an extent the answer just
        # said does not exist.
        {:error, {:bytes_on_ended_range, status, byte_size(bytes)}}
      else
        {:ok, {:up_range_data, ring, status, position, bytes}}
      end
    else
      {:error, refusal} -> {:error, refusal}
      _payload_ran_out -> shape(:up_range_data, sender, byte_size(payload))
    end
  end

  defp fields(type, sender, payload), do: shape(type, sender, byte_size(payload))

  defp greeting(:appliance, <<>>, _len), do: {:ok, {:hello, :appliance}}

  defp greeting(
         :server,
         <<log::unsigned-big-integer-64, capture::unsigned-big-integer-64>>,
         _len
       ),
       do: {:ok, {:hello, {:server, log, capture}}}

  # A greeting whose version matched but whose remaining fields did not. The
  # length owed is the floor for the sending end, which is what tells the two
  # greeting shapes apart in the refusal.
  defp greeting(sender, _rest, len), do: shape(:hello, sender, len)

  defp selected_ring(selector) do
    case ring_from_byte(selector) do
      {:ok, ring} -> {:ok, ring}
      :error -> {:error, {:unknown_ring, selector}}
    end
  end

  defp selected_status(code) do
    case range_status_from_byte(code) do
      {:ok, status} -> {:ok, status}
      :error -> {:error, {:unknown_range_status, code}}
    end
  end

  defp shape(type, sender, len) do
    {:error, {:payload_length, type, len, payload_floor(type, sender)}}
  end

  # The whole line, or where it stops being one. A newline counts as
  # unprintable: the payload is *one* line, so the frame delimits it and a byte
  # that would delimit it again is not part of it.
  defp first_unprintable(<<byte, _rest::binary>>, at)
       when byte < @first_printable or byte > @last_printable,
       do: {at, byte}

  defp first_unprintable(<<_byte, rest::binary>>, at), do: first_unprintable(rest, at + 1)
  defp first_unprintable(<<>>, _at), do: nil
end
