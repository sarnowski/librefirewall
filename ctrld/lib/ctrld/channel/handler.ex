defmodule Ctrld.Channel.Handler do
  @moduledoc """
  One appliance's channel session, from the greeting to whatever ended it.

  A connection arrives already mutually authenticated — the listener would not
  have produced one otherwise — so this process starts by reading who the peer is
  off the certificate the handshake validated, finds the appliance it names, and
  greets it. The server speaks first: its greeting carries the two resume cursors
  the appliance restarts each recording ring from, and the appliance answers with
  its own carrying a version. Everything after that is frames.

  ## What this server acknowledges

  The positions its ingest has durably stored each ring up to, which is the one
  thing it knows that the appliance cannot. They go out twice over: in the
  greeting, where they are the appliance's resume points, and again as `ack`
  frames while the session carries data, where they are what moves the
  appliance's own durable reader cursor on. Both read `Ctrld.Telemetry.Cursor`
  rather than a second notion of progress, so a position this server promises is
  always one an insert has been acknowledged for.

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

  A frame that is *legal* but that nothing here answers — range data, for which
  this server has sent no request, having no range reads — is counted and dropped
  rather than refused. An appliance speaking a part of the protocol this build
  does not yet answer is one running ahead of this server, and refusing it would
  make an upgrade of one end an outage of the pair. That is the same decision the
  appliance takes about frames this server has not yet learned to send, taken on
  the other end of the same wire. The count is reported once, when the session
  ends.

  ## The configuration transaction, over two connections

  This session drives one, and it is the only thing here that this server starts
  rather than answers. An administrator stages a document; the session sends
  `down_config_stage`, the appliance answers `up_config_validate_result`, and a
  document it took as its candidate is committed straight away with
  `down_config_commit` — one round trip, because there is nothing for an operator
  to decide between the verdict and the commit that they did not already decide by
  staging.

  **The commit ends the session, and that is the protocol working rather than
  failing.** The appliance closes on a commit precisely so that a confirmation
  cannot arrive on the connection that made it: a commit is provisional, an
  appliance whose management plane has become unreachable must undo it, and a
  confirmation over the same connection would prove nothing about reachability. So
  the confirmation is sent from `greeted/2` on the *next* connection, out of the
  row the commit wrote, and this session's ending is expected.

  A validate result that arrives for a version this server is not staging is
  counted and dropped like any other unanswerable frame. It has to be: the
  appliance is semi-trusted, so an unsolicited result is a frame a peer chose to
  send, and acting on one would let it move a version's state by asserting a
  verdict nobody asked for.
  """

  use ThousandIsland.Handler

  alias Ctrld.Appliances
  alias Ctrld.Appliances.{Appliance, ConfigurationVersion}
  alias Ctrld.Channel.{Decoder, Frame, Identity, Ingest, Sessions}
  alias Ctrld.Telemetry.Cursor
  alias ThousandIsland.Socket

  require Logger

  # How long the appliance is given to confirm a provisional commit, in seconds,
  # and it is the number the commit frame carries rather than a deadline this
  # server keeps: the appliance arms it off its own clock, because it is the end
  # that has to act when it expires.
  #
  # Sixty seconds. The appliance closes the session on the commit and re-dials on
  # a backoff that starts short, so a minute is several attempts' worth of room —
  # and the whole point of the bound is that an appliance whose management plane
  # has genuinely gone away undoes the change while somebody is still watching,
  # rather than hours later.
  @confirm_deadline_secs 60

  # How long an appliance has to answer the server's greeting with its own. The
  # session is authenticated by this point, so this is not the flood bound — that
  # is the handshake deadline and the connection ceiling below it. This is the
  # bound on a peer that completed a handshake and then did not get on with it,
  # which no working appliance does: its greeting is the first thing it writes.
  @default_greeting_timeout :timer.seconds(30)

  # The acknowledgement cadence the framing contract owes an appliance: once per
  # five seconds of received data, and once per eight mebibytes of ring bytes.
  # Whichever comes first, because the two answer different appliances — a busy
  # one reaches the volume long before the period, and a quiet one would wait
  # indefinitely on the volume alone.
  @default_ack_period :timer.seconds(5)
  @default_ack_bytes 8 * 1024 * 1024

  @typedoc """
  A session's state.

  `appliance` and `device_id` are established before the greeting is sent and do
  not change afterwards: a session is one appliance's, decided by a certificate,
  and there is no frame that could move it to another. `greet_by` is the monotonic
  instant the greeting is owed by, and it is an instant rather than a duration on
  purpose: a duration handed to the transport afresh on each arrival would be a
  bound a peer resets by sending a byte, so a peer dribbling one byte at a time
  would never meet it.   `ending` is how the session was decided to end where this
  end decided it, so the one line a close writes names the real cause rather than
  the transport's view of it.

  `acked_at` and `acked_after` are when the last acknowledgement went out and the
  received tally it went out on, which between them are the whole of the cadence:
  the period is measured from an instant this end chose and the volume from a
  tally only whole frames move, so neither is a bound a peer resets at will.

  `staging` is the generation this session has sent a document for and not yet had
  a verdict on, or `nil`. It is the whole of what makes an unsolicited validate
  result harmless: a result is acted on only while this session is waiting for
  one, so a peer asserting a verdict nobody asked for moves nothing.
  """
  @type state :: %{
          device_id: String.t() | nil,
          appliance: Appliance.t() | nil,
          decoder: Decoder.t(),
          greeted?: boolean(),
          greet_by: integer() | nil,
          received: non_neg_integer(),
          unanswered: non_neg_integer(),
          acked_at: integer() | nil,
          acked_after: non_neg_integer(),
          staging: pos_integer() | nil,
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
    setting(:greeting_timeout, @default_greeting_timeout)
  end

  @doc """
  How long a session may carry received data before an acknowledgement is owed.

  The deployment's value is the contract's five seconds; the suite shortens it,
  for `greeting_timeout/0`'s reason exactly.
  """
  @spec ack_period() :: pos_integer()
  def ack_period, do: setting(:ack_period, @default_ack_period)

  @doc """
  How many received ring bytes owe an acknowledgement whatever the clock says.

  The deployment's value is the contract's eight mebibytes; the suite lowers it,
  a test that shipped that much to prove the volume bound having nothing to say
  that a smaller one does not.
  """
  @spec ack_bytes() :: pos_integer()
  def ack_bytes, do: setting(:ack_bytes, @default_ack_bytes)

  defp setting(key, default) do
    :ctrld
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(key, default)
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
        frames
        |> dispatch(socket, %{state | decoder: decoder})
        |> acknowledge(socket)
        |> still_owed_a_greeting()

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

  # An operator's staging, arriving from a web request in another process. A
  # message and not a call, so the request does not wait on the appliance; what it
  # watches instead is the version's own state, which this session moves.
  #
  # A handler process is a `GenServer` whose state is the transport's
  # `{socket, state}` pair, and the answer goes back through the transport's own
  # continuation rather than being assembled here: that is what keeps the read
  # timer, the socket options and the close path identical to the ones every
  # arriving frame takes. A staging that could not be written closes the session,
  # which the continuation turns into the same orderly shutdown a refusal does.
  def handle_info({:stage_configuration, %ConfigurationVersion{} = version}, {socket, state}) do
    continuation =
      case stage(socket, state, version) do
        {:ok, state} -> {:continue, state}
        {:close, state} -> {:close, state}
      end

    ThousandIsland.Handler.handle_continuation(continuation, socket)
  end

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
    # And the registration goes with it, so an operator who sees the inventory
    # call this appliance online has somewhere to send a document. A second
    # session for one appliance does not displace the first — see
    # `Ctrld.Channel.Sessions` — and carries on unregistered, which costs it
    # nothing but the ability to be staged on.
    _ = Sessions.register(device_id)
    timeout = greeting_timeout()

    now = System.monotonic_time(:millisecond)

    state = %{
      new_state()
      | device_id: device_id,
        appliance: appliance,
        greet_by: now + timeout,
        acked_at: now
    }

    Logger.info("ctrld: channel session opened for appliance #{device_id}")

    {log, capture} = cursors(device_id)
    greeting = {:hello, {:server, log, capture}}

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
  # are the appliance's resume points — read from the one place a position is
  # held rather than kept a second time here, so what the greeting promises and
  # what an ingest would skip cannot come apart.
  #
  # It is a promise, and the direction it may err in is one way only. A position
  # **below** what this server holds costs bytes and never rows: the appliance
  # re-ships a run the ingest recognises and skips. A position **above** it names
  # a resume point nothing here has stored, and the recordings between the two
  # are lost for good. So the mark is the ingest's own, which never moves past an
  # insert the store acknowledged.
  defp cursors(device_id) do
    {Cursor.position(device_id, :log), Cursor.position(device_id, :capture)}
  end

  # The acknowledgement the framing contract owes an appliance while a session
  # is carrying data: the same two positions the greeting named, as they stand
  # now. It is what moves an appliance's own durable reader cursor on, so a
  # session that only ever greeted would leave every reconnect resuming from
  # wherever the last greeting found the ingest.
  #
  # **Owed on received data and never on a timer**, which is what keeps it off
  # the record bound this session states: a peer that says nothing is acked
  # nothing, and one that floods is acked at this end's cadence rather than at
  # its own. No line goes with it either — an acknowledgement is a frame, and
  # the session's two records are its opening and its ending.
  defp acknowledge({:continue, %{greeted?: true} = state} = carried, socket) do
    now = System.monotonic_time(:millisecond)

    if owed?(state, now) do
      {log, capture} = cursors(state.device_id)

      case send_frame(socket, {:ack, log, capture}) do
        :ok ->
          {:continue, %{state | acked_at: now, acked_after: state.received}}

        # A peer that was gone before the acknowledgement could reach it, on the
        # greeting's terms exactly: a connection this end could not write to is
        # a connection to close, under a name of its own so an operator reading
        # the closing line is not left with the transport's view of it.
        {:error, reason} ->
          {:close, %{state | ending: {:ack_not_sent, reason}}}
      end
    else
      carried
    end
  end

  defp acknowledge(carried, _socket), do: carried

  # Whichever bound comes first, and the volume is measured against the tally at
  # the last acknowledgement rather than reset by one: a frame that arrives while
  # the period is running still counts toward the next.
  defp owed?(%{received: received, acked_after: acked_after, acked_at: acked_at}, now) do
    received - acked_after >= ack_bytes() or
      (received > acked_after and now - acked_at >= ack_period())
  end

  defp dispatch([], _socket, state), do: {:continue, state}

  defp dispatch([frame | rest], socket, state) do
    case receive_frame(frame, socket, state) do
      {:ok, state} -> dispatch(rest, socket, state)
      {:close, state} -> {:close, state}
      {:refuse, refusal} -> refuse(socket, state, refusal)
    end
  end

  # The greeting, which must be the first frame and may be the only one of its
  # kind. A second is not one of the framing violations the contract lists — the
  # codec below has no notion of a conversation — so it is this session's own
  # rule: an appliance restarting a greeting mid-session is a shape the protocol
  # has nowhere to put, and accepting it would be accepting a peer's reset of a
  # conversation this end is keeping the state of.
  defp receive_frame({:hello, :appliance}, socket, %{greeted?: false} = state) do
    Logger.info(
      "ctrld: channel greeting agreed with appliance #{state.device_id} " <>
        "on protocol version #{Frame.version()}"
    )

    greeted(socket, %{state | greeted?: true})
  end

  defp receive_frame({:hello, :appliance}, _socket, _state), do: {:refuse, :second_greeting}

  defp receive_frame({:up_records, position, bytes}, _socket, state) do
    {:ok, received(state, :log, position, bytes)}
  end

  defp receive_frame({:up_capture, position, bytes}, _socket, state) do
    {:ok, received(state, :capture, position, bytes)}
  end

  # The verdict on the document this session staged, and only while it is waiting
  # for one: an unsolicited result is a frame a semi-trusted peer chose to send,
  # so it falls through to the unanswerable tally below rather than moving a
  # version's state.
  defp receive_frame({:up_config_validate_result, line}, socket, %{staging: generation} = state)
       when is_integer(generation) do
    validated(socket, %{state | staging: nil}, generation, line)
  end

  # Legal, and unanswerable by this build. Counted rather than logged per frame,
  # so a peer cannot drive this server's records: the tally goes out once, when
  # the session ends.
  defp receive_frame(_frame, _socket, state),
    do: {:ok, %{state | unanswered: state.unanswered + 1}}

  # What a fresh connection owes before anything else: the confirmation of a
  # commit made on a previous one. Sent here rather than when the commit was made,
  # because that is the protocol's whole point — the appliance ends the session on
  # a commit so that the confirmation has to travel a connection the appliance
  # established afterwards, which is what makes it evidence that this server is
  # still reachable.
  #
  # A version with no confirmation owed is the ordinary case and says nothing.
  defp greeted(socket, state) do
    case Appliances.awaiting_confirmation(state.device_id) do
      nil ->
        {:ok, state}

      %ConfigurationVersion{generation: generation} ->
        confirm(socket, state, generation)
    end
  end

  defp confirm(socket, state, generation) do
    case send_frame(socket, {:down_commit_confirm, generation}) do
      :ok ->
        {:ok, _version} =
          Appliances.configuration_confirmed(state.device_id, generation, DateTime.utc_now())

        Logger.info(
          "ctrld: confirmed generation #{generation} on appliance #{state.device_id} " <>
            "over a fresh connection"
        )

        {:ok, state}

      # A peer that hung up between the greeting and this frame. Its own ending,
      # and the version stays awaiting a confirmation: the next connection owes
      # the same one, which is exactly right — an appliance that never gets a
      # confirmation rolls the commit back on its own deadline, and this server
      # keeps trying until one of the two happens.
      {:error, reason} ->
        {:close, %{state | ending: {:confirmation_not_sent, reason}}}
    end
  end

  # The appliance's verdict, recorded, and then the commit it earns. One round
  # trip and no second decision for an operator to take: staging a document IS
  # the decision, and a verdict that says the appliance took it as its candidate
  # is the only thing that was in doubt.
  defp validated(socket, state, generation, line) do
    {:ok, version} =
      Appliances.configuration_validated(state.device_id, generation, line, DateTime.utc_now())

    if ConfigurationVersion.accepted?(line) do
      commit(socket, state, staged_generation(version, generation))
    else
      Logger.info(
        "ctrld: appliance #{state.device_id} refused the document staged as generation " <>
          "#{generation}: #{line}"
      )

      {:ok, state}
    end
  end

  # The generation the COMMIT names, taken from the appliance's own result line
  # where it stated one. The appliance's datastore is the authority on the number
  # a commit must carry — it refuses one that is not the number it would assign —
  # so reading it back is what keeps a commit from being refused for having
  # proposed a generation this server merely believed in.
  defp staged_generation(%ConfigurationVersion{validation_result: line}, fallback)
       when is_binary(line) do
    ConfigurationVersion.stated_generation(line) || fallback
  end

  defp staged_generation(%ConfigurationVersion{}, fallback), do: fallback

  # The document goes down the wire and the generation is remembered, which is
  # what makes the verdict that comes back one this session asked for.
  #
  # A staging while another is outstanding is dropped rather than sent: the
  # appliance holds one candidate, so two documents in flight would leave the
  # second's verdict arriving against the first's generation. The context refuses a
  # second staging before it gets here, so this is the belt to that braces — and it
  # says so on the way past, because a document an operator staged and nothing sent
  # is worth a line.
  defp stage(socket, %{staging: outstanding} = state, version) when is_integer(outstanding) do
    Logger.warning(
      "ctrld: not staging generation #{version.generation} on appliance #{state.device_id}: " <>
        "generation #{outstanding} is still awaiting the appliance's verdict"
    )

    _ = socket
    {:ok, state}
  end

  defp stage(socket, state, %ConfigurationVersion{} = version) do
    case send_frame(socket, {:down_config_stage, version.document}) do
      :ok ->
        Logger.info(
          "ctrld: staged generation #{version.generation} on appliance #{state.device_id}, " <>
            "#{byte_size(version.document)} document byte(s)"
        )

        {:ok, %{state | staging: version.generation}}

      {:error, reason} ->
        {:close, %{state | ending: {:stage_not_sent, reason}}}
    end
  end

  defp commit(socket, state, generation) do
    case send_frame(socket, {:down_config_commit, generation, @confirm_deadline_secs}) do
      :ok ->
        {:ok, _version} =
          Appliances.configuration_committed(state.device_id, generation, DateTime.utc_now())

        Logger.info(
          "ctrld: committed generation #{generation} on appliance #{state.device_id} " <>
            "provisionally, to be confirmed within #{@confirm_deadline_secs}s over a fresh " <>
            "connection"
        )

        {:ok, state}

      {:error, reason} ->
        {:close, %{state | ending: {:commit_not_sent, reason}}}
    end
  end

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

      # Unreachable from anything a peer sends, and that claim now has to cover
      # five frames rather than one. The greeting's fields and the
      # acknowledgement's are positions out of `cursors/1`; the commit's and the
      # confirmation's are a generation out of this server's own row; and the
      # staged document is held to `Ctrld.Configuration.maximum_bytes/0` before a
      # version exists, which is the codec's own document bound. So a refusal
      # here is a defect in this module or in the codec, and it fails visibly
      # rather than closing a session as though the appliance had done something.
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
      acked_at: nil,
      acked_after: 0,
      staging: nil,
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

  def describe({:ack_not_sent, reason}),
    do: "this server's acknowledgement was not sent: #{inspect(reason)}"

  def describe({:stage_not_sent, reason}),
    do: "a staged document was not sent: #{inspect(reason)}"

  def describe({:commit_not_sent, reason}),
    do: "a provisional commit was not sent: #{inspect(reason)}"

  def describe({:confirmation_not_sent, reason}),
    do: "a commit's confirmation was not sent: #{inspect(reason)}"

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
