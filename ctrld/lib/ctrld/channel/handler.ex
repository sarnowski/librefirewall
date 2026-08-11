defmodule Ctrld.Channel.Handler do
  @moduledoc """
  One appliance's channel session, from the greeting to whatever ended it.

  A connection arrives already mutually authenticated — the listener would not
  have produced one otherwise — so this process starts by reading who the peer is
  off the certificate the handshake validated, finds the appliance it names, and
  greets it. The server speaks first: its greeting carries the two resume cursors
  the appliance restarts each recording ring from, and the appliance answers with
  its own carrying a version. Everything after that is frames.

  ## Adversary

  A **semi-trusted appliance, up to and including a compromised one**. It chose
  every byte after the handshake and the pacing of every arrival, and holding a
  certificate this server issued buys it nothing here beyond being named.

  What that means concretely: a peer's bytes reach `Ctrld.Channel.Decoder` and
  nothing else, no value the peer sent becomes an atom or reaches a query, and no
  payload byte reaches a log line. **The number of records a session leaves is
  bounded by the shape of its outcome and not by anything that happened on the
  wire** — one line when it opens, one when it ends, and one where a connection
  was refused before it became a session — so a peer that breaks the protocol a
  thousand times over leaves the same lines as one that breaks it once.

  ## What ends a session, and what does not

  A framing violation closes the connection and nothing else happens: there is no
  resynchronisation, because a stream whose framing is wrong has no next frame.
  So does a greeting that never arrives, a second greeting, and a session that
  goes silent. Every one of them is a value with a name, because a connection
  that closed for "a protocol error" tells an operator nothing they can act on.

  The greeting has an **absolute** deadline rather than one per arrival, and that
  distinction is the whole of what bounds a peer here: the transport's timeout is
  handed the time still left on the deadline the session opened under, so a peer
  that sends one byte at a time without ever completing a greeting is dropped on
  the same clock as one that sends nothing. It cannot hold a connection process
  by staying just barely alive, and while it holds one it costs at most a single
  frame's worth of buffer — the decoder holds one frame and never two — with the
  listener's connection ceiling bounding how many such peers there can be at once.

  A frame that is *legal* but that nothing here answers — a validate result or
  range data, for which this server has sent no request, having no configuration
  operations and no range reads — is counted and dropped rather than refused. An
  appliance speaking a part of the protocol this build does not yet answer is one
  running ahead of this server, and refusing it would make an upgrade of one end
  an outage of the pair. That is the same decision the appliance takes about
  frames this server has not yet learned to send, taken on the other end of the
  same wire. The count is reported once, when the session ends.
  """

  use ThousandIsland.Handler

  alias Ctrld.Appliances
  alias Ctrld.Appliances.Appliance
  alias Ctrld.Channel.{Decoder, Frame, Identity, Ingest}
  alias ThousandIsland.Socket

  require Logger

  # How long an appliance has to answer the server's greeting with its own. The
  # session is authenticated by this point, so this is not the flood bound — that
  # is the handshake deadline and the connection ceiling below it. This is the
  # bound on a peer that completed a handshake and then did not get on with it,
  # which no working appliance does: its greeting is the first thing it writes.
  @default_greeting_timeout :timer.seconds(30)

  @typedoc """
  A session's state.

  `appliance` and `device_id` are established before the greeting is sent and do
  not change afterwards: a session is one appliance's, decided by a certificate,
  and there is no frame that could move it to another. `greet_by` is the monotonic
  instant the greeting is owed by, and it is an instant rather than a duration on
  purpose: a duration handed to the transport afresh on each arrival would be a
  bound a peer resets by sending a byte, so a peer dribbling one byte at a time
  would never meet it. `ending` is how the session was decided to end where this
  end decided it, so the one line a close writes names the real cause rather than
  the transport's view of it.
  """
  @type state :: %{
          device_id: String.t() | nil,
          appliance: Appliance.t() | nil,
          decoder: Decoder.t(),
          greeted?: boolean(),
          greet_by: integer() | nil,
          received: non_neg_integer(),
          unanswered: non_neg_integer(),
          ending: term() | nil
        }

  @doc """
  How long an appliance has to greet, from the instant this server greets it.

  The deployment's value is the default; the suite shortens it, because a test
  that proves a peer which never greets is dropped has to wait for the deadline to
  pass and waiting thirty seconds for it would be paid on every run.
  """
  @spec greeting_timeout() :: pos_integer()
  def greeting_timeout do
    :ctrld
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(:greeting_timeout, @default_greeting_timeout)
  end

  @impl ThousandIsland.Handler
  def handle_connection(socket, _options) do
    case Identity.appliance(peer_certificate(socket)) do
      {:ok, device_id, appliance} -> open(socket, device_id, appliance)
      {:error, refusal} -> refuse_connection(socket, refusal)
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(bytes, socket, state) do
    case Decoder.absorb(state.decoder, bytes) do
      {:ok, frames, decoder} ->
        frames |> dispatch(socket, %{state | decoder: decoder}) |> still_owed_a_greeting()

      {:refused, refusal, frames, decoder} ->
        # The frames that completed before the violation were whole frames and
        # are taken. The violation then ends the session, because where the frame
        # after it starts is exactly what has been lost — unless dispatching
        # those frames already ended it, in which case the first cause is the one
        # reported.
        case dispatch(frames, socket, %{state | decoder: decoder}) do
          {:continue, state} -> refuse(socket, state, {:framing, refusal})
          {:close, state} -> {:close, state}
        end
    end
  end

  # A session that has not greeted yet keeps the deadline it was opened under,
  # expressed as the time still left on it. So the bound is absolute: a peer that
  # dribbles bytes without completing a greeting runs the same clock down as one
  # that says nothing, rather than restarting it with each arrival. Once greeted,
  # the listener's read timeout is the bound and the transport applies it.
  defp still_owed_a_greeting({:continue, %{greeted?: false, greet_by: greet_by} = state}) do
    {:continue, state, max(greet_by - System.monotonic_time(:millisecond), 0)}
  end

  defp still_owed_a_greeting(other), do: other

  @impl ThousandIsland.Handler
  def handle_close(_socket, state), do: ended(state, :peer_closed)

  @impl ThousandIsland.Handler
  def handle_error(reason, _socket, state), do: ended(state, {:failed, reason})

  @impl ThousandIsland.Handler
  def handle_shutdown(_socket, state), do: ended(state, :server_shutdown)

  @impl ThousandIsland.Handler
  def handle_timeout(_socket, %{greeted?: greeted?} = state) do
    ended(state, if(greeted?, do: :idle_timeout, else: :greeting_timeout))
  end

  defp open(socket, device_id, appliance) do
    # The row moves before the greeting goes out, so an appliance that reads a
    # greeting is one the inventory already calls online: the other order leaves a
    # window in which the appliance believes it has a session and the inventory
    # says it has none.
    {:ok, appliance} = Appliances.session_opened(appliance, DateTime.utc_now())
    timeout = greeting_timeout()

    state = %{
      new_state()
      | device_id: device_id,
        appliance: appliance,
        greet_by: System.monotonic_time(:millisecond) + timeout
    }

    Logger.info("ctrld: channel session opened for appliance #{device_id}")

    greeting = {:hello, {:server, log_cursor(appliance), capture_cursor(appliance)}}

    case send_frame(socket, greeting) do
      :ok ->
        {:continue, state, timeout}

      # A peer that completed a handshake and was gone before the greeting could
      # reach it. Ordinary, and its own named ending rather than a failure: a
      # connection this end could not write to is a connection to close, and
      # answering the transport with an error instead would leave an operator a
      # crash report with a stack trace for something a peer did — which is the
      # one thing the record bound above exists to prevent.
      {:error, reason} ->
        {:close, %{state | ending: {:greeting_not_sent, reason}}}
    end
  end

  # The positions up to which this server has durably ingested each ring, which
  # are the appliance's resume points. There is no durable ingest on this side of
  # the wire yet — the bytes reach `Ctrld.Channel.Ingest` and are counted — so the
  # honest cursor is the beginning of each ring: an appliance resuming from zero
  # re-ships history this server did not keep, and delivery being at-least-once
  # that is a duplicate rather than a loss. A cursor naming a position nothing
  # here has stored would be the other way round, and that one loses recordings.
  defp log_cursor(%Appliance{}), do: 0
  defp capture_cursor(%Appliance{}), do: 0

  defp dispatch([], _socket, state), do: {:continue, state}

  defp dispatch([frame | rest], socket, state) do
    case receive_frame(frame, state) do
      {:ok, state} -> dispatch(rest, socket, state)
      {:refuse, refusal} -> refuse(socket, state, refusal)
    end
  end

  # The greeting, which must be the first frame and may be the only one of its
  # kind. A second is not one of the framing violations the contract lists — the
  # codec below has no notion of a conversation — so it is this session's own
  # rule: an appliance restarting a greeting mid-session is a shape the protocol
  # has nowhere to put, and accepting it would be accepting a peer's reset of a
  # conversation this end is keeping the state of.
  defp receive_frame({:hello, :appliance}, %{greeted?: false} = state) do
    Logger.info(
      "ctrld: channel greeting agreed with appliance #{state.device_id} " <>
        "on protocol version #{Frame.version()}"
    )

    {:ok, %{state | greeted?: true}}
  end

  defp receive_frame({:hello, :appliance}, _state), do: {:refuse, :second_greeting}

  defp receive_frame({:up_records, position, bytes}, state) do
    {:ok, received(state, :log, position, bytes)}
  end

  defp receive_frame({:up_capture, position, bytes}, state) do
    {:ok, received(state, :capture, position, bytes)}
  end

  # Legal, and unanswerable by this build. Counted rather than logged per frame,
  # so a peer cannot drive this server's records: the tally goes out once, when
  # the session ends.
  defp receive_frame(_frame, state), do: {:ok, %{state | unanswered: state.unanswered + 1}}

  # The ring bytes cross the seam, and the arrival is announced. Both, in this
  # order, and neither is the other's business: the seam is what eventually reads
  # the recording, and the announcement is what a live view of this appliance
  # watches — so an announcement carries a count and never the bytes, and it
  # happens whichever implementation is configured behind the seam.
  #
  # The tally moves either way, so how much a session carried is a fact about the
  # session rather than about whatever ingested it.
  defp received(state, ring, position, bytes) do
    :ok = Ingest.ring_bytes(state.device_id, ring, position, bytes)
    :ok = Appliances.telemetry_received(state.device_id, ring, position, byte_size(bytes))
    %{state | received: state.received + byte_size(bytes)}
  end

  # No line here: the session's one closing record carries the cause, so a
  # refusal that also closes would otherwise be reported twice.
  defp refuse(socket, state, refusal) do
    _ = Socket.shutdown(socket, :write)
    {:close, %{state | ending: refusal}}
  end

  # A connection with no appliance behind it never became a session, so there is
  # no row to move and nothing to announce — only a refusal to record and a socket
  # to shut. The peer address is what places it, and it is the one fact about the
  # peer worth a line here.
  defp refuse_connection(socket, refusal) do
    Logger.warning(
      "ctrld: channel connection from #{peer_address(socket)} refused: " <>
        Identity.describe(refusal)
    )

    _ = Socket.shutdown(socket, :write)
    {:close, new_state()}
  end

  defp ended(%{appliance: %Appliance{} = appliance} = state, fallback) do
    {:ok, _appliance} = Appliances.session_closed(appliance, DateTime.utc_now())

    Logger.info(
      "ctrld: channel session closed for appliance #{state.device_id} " <>
        "(#{describe(state.ending || fallback)}), having carried #{state.received} " <>
        "recording byte(s)" <> unanswered(state)
    )

    :ok
  end

  # A connection that was refused before it became a session, or one that never
  # got that far. Its own refusal was recorded where it happened.
  defp ended(_state, _fallback), do: :ok

  defp unanswered(%{unanswered: 0}), do: ""

  defp unanswered(%{unanswered: count}),
    do: ", having dropped #{count} frame(s) this build does not answer"

  defp send_frame(socket, frame) do
    case Frame.encode(:server, frame) do
      {:ok, bytes} ->
        Socket.send(socket, bytes)

      # Unreachable from anything a peer sends: the only frame this build
      # composes is the server greeting, and every field in it is a constant of
      # `log_cursor/1` and `capture_cursor/1`. So a refusal here is a defect in
      # this module or in the codec, and it fails visibly rather than closing a
      # session as though the appliance had done something.
      {:error, refusal} ->
        raise "ctrld composed an unsendable channel frame: #{inspect(refusal)}"
    end
  end

  defp peer_certificate(socket) do
    case Socket.peercert(socket) do
      {:ok, der} -> der
      {:error, _reason} -> nil
    end
  end

  defp peer_address(socket) do
    case Socket.peername(socket) do
      {:ok, {address, port}} -> "#{:inet.ntoa(address)}:#{port}"
      {:error, _reason} -> "an unreadable address"
    end
  end

  defp new_state do
    %{
      device_id: nil,
      appliance: nil,
      decoder: Decoder.new(:appliance),
      greeted?: false,
      greet_by: nil,
      received: 0,
      unanswered: 0,
      ending: nil
    }
  end

  @doc """
  Why a session ended, in the words an operator needs.

  One phrase per cause and none standing for several: a peer that closed, a
  greeting that never came, a stream that went quiet and each way the framing can
  be broken are different things to go and look at. A framing refusal renders as
  its own name and never as the peer's bytes.
  """
  @spec describe(term()) :: String.t()
  def describe(:peer_closed), do: "the appliance closed the connection"
  def describe(:server_shutdown), do: "this server is shutting down"
  def describe(:greeting_timeout), do: "the appliance sent no greeting"
  def describe(:idle_timeout), do: "the appliance sent nothing for the read timeout"
  def describe(:second_greeting), do: "the appliance sent a second greeting"

  def describe({:greeting_not_sent, reason}),
    do: "this server's greeting was not sent: #{inspect(reason)}"

  def describe({:failed, reason}), do: "the connection failed: #{inspect(reason)}"
  def describe({:framing, refusal}), do: "the framing was broken: #{describe_refusal(refusal)}"

  defp describe_refusal({:reserved_non_zero, at, _byte}),
    do: "reserved header byte #{at} is not zero"

  defp describe_refusal({:unknown_type, _byte}), do: "the type byte names no frame"

  defp describe_refusal({:payload_too_long, stated}),
    do: "a header states #{stated} payload bytes, past the bound of #{Frame.max_payload_length()}"

  defp describe_refusal({:wrong_direction, type, sender}),
    do: "a #{type} frame may not travel from the #{sender}"

  defp describe_refusal({:first_frame_not_hello, type}),
    do: "the first frame is a #{type} and not the greeting"

  defp describe_refusal({:version_mismatch, theirs}),
    do:
      "the appliance speaks protocol version #{theirs} and this server speaks #{Frame.version()}"

  defp describe_refusal({:payload_length, type, len, needed}),
    do: "a #{type} payload of #{len} bytes is not the #{needed} its fields need"

  defp describe_refusal({:unknown_ring, _byte}), do: "a ring selector names neither recording"

  defp describe_refusal({:unknown_range_status, _byte}),
    do: "a range answer's status byte names no status"

  defp describe_refusal({:bytes_on_ended_range, status, len}),
    do: "a range answer that ended with #{status} carries #{len} bytes anyway"

  defp describe_refusal({:config_document_too_long, len}),
    do: "a staged document of #{len} bytes is past the bound of #{Frame.max_document_length()}"

  defp describe_refusal({:result_line_not_printable, at, _byte}),
    do: "a validate-result line carries an unprintable byte at offset #{at}"
end
