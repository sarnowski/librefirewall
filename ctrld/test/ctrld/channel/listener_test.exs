defmodule Ctrld.Channel.ListenerTest do
  @moduledoc """
  A real listener, a real TLS client, and a real handshake.

  Nothing here is faked: the listener is the one the supervision tree starts, the
  certificate it serves is one this server's own authority issued for the address
  the client dials, the client presents a device certificate that authority
  issued too, and the greeting that crosses is the contract's own bytes. What is
  proved is therefore the whole path — mutual authentication, the identity read
  off the peer certificate, the greeting exchange, frames in both directions, and
  the inventory moving with the session.

  Every session here is established over the one key-exchange group the appliance
  offers, so what the suite exercises is the pair rather than this end alone; the
  group has a describe block of its own, which holds the hybrid to a client that
  offers nothing else and holds this end to offering nothing else either.

  The suite is not async: a listener binds a real port, and the sandbox
  connection has to be shared with the connection processes the listener spawns,
  which are not the test's own.
  """

  use Ctrld.DataCase, async: false

  alias Ctrld.Appliances
  alias Ctrld.Appliances.ConfigurationVersion
  alias Ctrld.Channel.{Frame, Handler, Ingest, Listener, Transport}
  alias Ctrld.PKI.EndpointCertificate
  alias Ctrld.Telemetry.Cursor

  @moduletag :capture_log

  @loopback {127, 0, 0, 1}

  setup do
    authority = authority_fixture()
    _endpoint_certificate = endpoint_certificate_fixture(loopback_endpoint())
    %{anchor: authority.certificate_der}
  end

  describe "the session an appliance gets" do
    test "the server greets first, with the two resume cursors", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)

      # The greeting is read with `greeted?` false, so a first frame that was
      # anything else would be refused here rather than interpreted.
      assert {:ok, {:hello, {:server, log, capture}}} = read_frame(socket)
      assert log == 0
      assert capture == 0

      :ok = :ssl.close(socket)
    end

    test "the greeting carries what the ingest has durably stored", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()

      # The one place a position is held, written as an ingest writes it. What
      # the greeting must then carry is these two numbers and not a second
      # notion of progress kept beside them.
      :ok = Cursor.advance(appliance.device_id, :log, 65_536)
      :ok = Cursor.advance(appliance.device_id, :capture, 131_072)

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 65_536, 131_072}}} = read_frame(socket)

      :ok = :ssl.close(socket)
    end

    test "a session carrying data is acknowledged, and one that only greeted is not", %{
      anchor: anchor
    } do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      # A greeting is not received data, so nothing is owed for it. The bound is
      # generous against the configured period, so a passing assertion here is
      # the rule and not the timing.
      :ok = send_frame(socket, {:hello, :appliance})
      assert {:error, :timeout} = :ssl.recv(socket, 0, Handler.ack_period() * 4)

      # The ingest stores a run and the appliance ships past it, which is the
      # whole shape an acknowledgement exists to close: the position that comes
      # back is the ingest's own and not the position the frame stated.
      :ok = Cursor.advance(appliance.device_id, :log, 4_096)
      :ok = send_frame(socket, {:up_records, 4_096, String.duplicate("l", 32)})

      assert {:ok, {:ack, 4_096, 0}} = read_frame(socket, true)

      :ok = :ssl.close(socket)
    end

    test "the volume bound acknowledges without waiting for the period", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      :ok = send_frame(socket, {:hello, :appliance})

      # One frame past the configured volume, delivered at once: a peer that
      # reaches the bound is acknowledged on the frame that reaches it rather
      # than on the clock, which is what keeps a busy appliance's reader cursor
      # moving at the rate it is actually shipping.
      :ok = send_frame(socket, {:up_records, 0, String.duplicate("r", Handler.ack_bytes())})

      assert {:ok, {:ack, 0, 0}} = read_frame(socket, true)

      :ok = :ssl.close(socket)
    end

    test "the greeting exchange completes and ring bytes reach the seam", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()
      device_id = appliance.device_id
      handler = attach_ingest_telemetry()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      :ok = send_frame(socket, {:hello, :appliance})
      :ok = send_frame(socket, {:up_records, 4096, "the log ring's own bytes"})
      :ok = send_frame(socket, {:up_capture, 8192, "the capture ring's own bytes"})

      assert_receive {:ingest, %{bytes: 24, position: 4096},
                      %{ring: :log, device_id: ^device_id}},
                     2_000

      assert_receive {:ingest, %{bytes: 28, position: 8192},
                      %{ring: :capture, device_id: ^device_id}},
                     2_000

      :ok = :ssl.close(socket)
      :ok = :telemetry.detach(handler)
    end

    test "the two frames cross even when the stream is cut mid-frame", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()
      device_id = appliance.device_id
      handler = attach_ingest_telemetry()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      # The greeting and an upstream frame, delivered a byte at a time: the
      # listener's decoder has to reassemble across arrivals it does not choose.
      {:ok, greeting} = Frame.encode(:appliance, {:hello, :appliance})
      {:ok, records} = Frame.encode(:appliance, {:up_records, 1, "one byte at a time"})
      bytes = IO.iodata_to_binary([greeting, records])

      for <<byte <- bytes>>, do: :ok = :ssl.send(socket, <<byte>>)

      assert_receive {:ingest, %{bytes: 18, position: 1}, %{ring: :log, device_id: ^device_id}},
                     5_000

      :ok = :ssl.close(socket)
      :ok = :telemetry.detach(handler)
    end

    test "the inventory says online while the session is open and offline after", %{
      anchor: anchor
    } do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()

      assert Appliances.status(reload(appliance)) == :onboarded

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      assert eventually(fn -> Appliances.status(reload(appliance)) == :online end)
      assert reload(appliance).connected_since

      :ok = :ssl.close(socket)

      assert eventually(fn -> Appliances.status(reload(appliance)) == :offline end)
      reloaded = reload(appliance)
      refute reloaded.connected_since
      assert reloaded.last_seen_at
    end

    test "a session announces itself on the fleet topic and the appliance's own", %{
      anchor: anchor
    } do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()
      device_id = appliance.device_id

      :ok = Appliances.subscribe()
      :ok = Appliances.subscribe(device_id)

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      # The same message on both topics, so a view of one appliance and a view of
      # the fleet handle one shape.
      assert_receive {:appliance_connected, ^device_id, %DateTime{}}, 2_000
      assert_receive {:appliance_connected, ^device_id, %DateTime{}}, 2_000

      :ok = :ssl.close(socket)

      assert_receive {:appliance_disconnected, ^device_id, %DateTime{}}, 2_000
      assert_receive {:appliance_disconnected, ^device_id, %DateTime{}}, 2_000
    end

    test "ring bytes are announced on the appliance's own topic and not the fleet's", %{
      anchor: anchor
    } do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()
      device_id = appliance.device_id

      :ok = Appliances.subscribe()
      :ok = Appliances.subscribe(device_id)

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      assert_receive {:appliance_connected, ^device_id, %DateTime{}}, 2_000
      assert_receive {:appliance_connected, ^device_id, %DateTime{}}, 2_000

      :ok = send_frame(socket, {:hello, :appliance})
      :ok = send_frame(socket, {:up_records, 4096, "the log ring's own bytes"})
      :ok = send_frame(socket, {:up_capture, 64, "and the capture ring's"})

      # A count and where it started, and not one byte of what arrived: those
      # bytes are a customer's captured traffic and a topic is not a recording.
      assert_receive {:appliance_telemetry, ^device_id, :log, 4096, 24}, 2_000
      assert_receive {:appliance_telemetry, ^device_id, :capture, 64, 22}, 2_000

      # Once each, so the fleet topic carried neither: a view of the whole
      # inventory is not woken by every appliance's every flush.
      refute_receive {:appliance_telemetry, _device_id, _ring, _position, _bytes}, 200

      :ok = :ssl.close(socket)
    end

    test "a framing violation closes the session", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      :ok = send_frame(socket, {:hello, :appliance})
      # A type byte naming no frame this protocol has.
      :ok = :ssl.send(socket, <<0::32, 0xFF, 0, 0, 0>>)

      assert {:error, ended} = :ssl.recv(socket, 0, 5_000)
      assert ended in [:closed, :einval]

      # And the row is honest about it afterwards.
      assert eventually(fn -> Appliances.status(reload(appliance)) == :offline end)
    end

    test "a first frame that is not the greeting closes the session", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      :ok = send_frame(socket, {:up_records, 0, "before any greeting"})

      assert {:error, ended} = :ssl.recv(socket, 0, 5_000)
      assert ended in [:closed, :einval]
    end
  end

  describe "the suite and the group, as negotiated" do
    test "the runtime this listener is built on offers the hybrid group at all" do
      # Not a restatement of `supported_groups/0` but the capability underneath
      # it: `:crypto` takes ML-KEM from the OpenSSL it is linked against rather
      # than implementing it, so a builder base whose OpenSSL predates 3.5
      # carries no KEM, `:ssl` drops every hybrid group, and the listener stops
      # starting. Asserted once here so that regression reads as the base image
      # rather than as every other test in this file failing to bind a port.
      assert :x25519mlkem768 in :ssl.groups()
    end

    test "a client offering only X25519MLKEM768 completes the handshake", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      # The appliance's own offer, written out rather than read back off the
      # listener: what has to hold is that this end meets *that* set, and a
      # client mirroring the server's option would prove only that this module
      # agrees with itself.
      options = client_options(certificate, key, anchor, [:x25519mlkem768])

      assert {:ok, socket} = :ssl.connect(@loopback, port, options, 5_000)
      assert {:ok, information} = :ssl.connection_information(socket)

      assert information[:protocol] == :"tlsv1.3"

      assert information[:selected_cipher_suite] == %{
               key_exchange: :any,
               cipher: :chacha20_poly1305,
               mac: :aead,
               prf: :sha256
             }

      # Established is not the same as usable, so the server's greeting has to
      # cross it too: the whole path an appliance takes, under the group an
      # appliance actually offers.
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      # Which group carried it is not in the connection information — OTP names
      # no negotiated group there — and does not need to be. Both ends offered
      # exactly one group, and a handshake that completed means those were the
      # same one; the refusal below is the other half of that argument, holding
      # this end to offering nothing besides.
      :ok = :ssl.close(socket)
    end

    test "a client offering only the hybrid's classical half gets no session", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      options = client_options(certificate, key, anchor, [:x25519])

      # No shared group, so the refusal lands before either certificate is
      # looked at. This is the assertion that widening the listener's group list
      # has to break: `x25519` offered beside the hybrid would admit this peer
      # and settle on the classical half alone, which is what offering one group
      # exists to prevent.
      assert {:error, _reason} = :ssl.connect(@loopback, port, options, 5_000)
    end
  end

  describe "the certificate the server serves" do
    test "carries the dialled address as a subject alternative name", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, served} = :ssl.peercert(socket)
      decoded = :public_key.pkix_decode_cert(served, :otp)

      # The check an appliance makes: the certificate is held to the address
      # literal that was dialled, and to no name.
      assert :public_key.pkix_verify_hostname(decoded, [{:ip, @loopback}])
      refute :public_key.pkix_verify_hostname(decoded, [{:ip, {10, 0, 0, 1}}])

      :ok = :ssl.close(socket)
    end
  end

  describe "a connection that is refused" do
    test "a certificate from another authority never becomes a session", %{anchor: anchor} do
      port = start_listener()
      foreign = foreign_device_certificate_fixture()

      # The client still validates the server against this server's own anchor,
      # so what fails is the server's verdict on the client and not the reverse.
      assert :refused = attempt(port, foreign.der, foreign.key, anchor)
    end

    test "a certificate naming no appliance never becomes a session", %{anchor: anchor} do
      port = start_listener()
      # Issued by this server's own authority, so the handshake itself succeeds,
      # and naming a device this server holds no row for, so nothing follows it.
      stranger = device_certificate_fixture(device_id())

      assert :refused = attempt(port, stranger.der, stranger.key, anchor)
    end

    test "no client certificate at all never becomes a session", %{anchor: anchor} do
      port = start_listener()

      options =
        [
          mode: :binary,
          active: false,
          verify: :verify_peer,
          cacerts: [anchor],
          versions: [:"tlsv1.3"],
          ciphers: Listener.cipher_suites(),
          supported_groups: Listener.supported_groups(),
          server_name_indication: :disable
        ]

      assert :refused = judge(:ssl.connect(@loopback, port, options, 5_000))
    end
  end

  describe "what bounds an unauthenticated peer" do
    test "a peer that opens a connection and never speaks TLS is dropped" do
      port = start_listener()

      # A bare TCP connection: no TLS at all, which is what a peer probing the
      # port looks like. It is dropped on the transport's own deadline rather
      # than on a wait this test invents.
      assert {:ok, socket} = :gen_tcp.connect(@loopback, port, [:binary, active: false], 5_000)

      assert {:error, :closed} =
               :gen_tcp.recv(socket, 0, Transport.handshake_timeout() * 4 + 2_000)
    end
  end

  describe "what bounds a peer that got through the handshake" do
    test "one that never greets is dropped on the greeting deadline", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      # Nothing is sent back. The deadline is the whole of what ends this.
      assert {:error, ended} = :ssl.recv(socket, 0, Handler.greeting_timeout() * 4 + 2_000)
      assert ended in [:closed, :einval]
    end

    test "one that dribbles bytes without greeting is dropped on the same deadline", %{
      anchor: anchor
    } do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)

      # A byte every so often, and never a whole greeting. The deadline is
      # absolute rather than per arrival, so this peer buys nothing by staying
      # barely alive — which is the property, an arrival-reset bound being one a
      # peer holds a connection process open with forever.
      dribbler =
        spawn_link(fn ->
          Enum.each(1..1_000, fn _ ->
            :ssl.send(socket, <<0>>)
            Process.sleep(div(Handler.greeting_timeout(), 10))
          end)
        end)

      assert {:error, ended} = :ssl.recv(socket, 0, Handler.greeting_timeout() * 4 + 2_000)
      assert ended in [:closed, :einval]
      Process.unlink(dribbler)
      Process.exit(dribbler, :kill)
    end
  end

  describe "the configuration transaction an administrator drives" do
    test "a document is staged, committed on the verdict, and confirmed on the next connection",
         %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, actor: actor, certificate: certificate, key: key} = appliance_with()
      document = amended_document()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      :ok = send_frame(socket, {:hello, :appliance})
      assert eventually(fn -> Appliances.status(reload(appliance)) == :online end)

      # The administrator's action, from this process. It returns as soon as the
      # session has been asked, which is why the frame is waited for below rather
      # than assumed to have gone already.
      assert {:ok, staged} = Appliances.stage_configuration(reload(appliance), document, actor)
      assert staged.generation == 2
      assert version(appliance, 2) |> ConfigurationVersion.state() == :staging

      assert {:ok, {:down_config_stage, ^document}} = read_frame(socket, true)

      # The appliance's verdict, in the appliance's own field vocabulary — the one
      # `pd_runtime`'s result line composes, so what this proves is the grammar the
      # pair actually shares rather than a shape invented here.
      :ok =
        send_frame(
          socket,
          {:up_config_validate_result, "generation=2 outcome=staged changes=3"}
        )

      # The commit follows the verdict with no second decision from anybody, and
      # it names the generation the appliance stated rather than the one this
      # server proposed.
      assert {:ok, {:down_config_commit, 2, deadline}} = read_frame(socket, true)
      assert deadline > 0

      # And nothing is recorded until the appliance says what it did with the
      # commit: it can commit and then put the commit back, so the row moves on the
      # answer rather than on the send.
      assert version(appliance, 2) |> ConfigurationVersion.state() == :staged

      :ok =
        send_frame(
          socket,
          {:up_config_validate_result, "generation=2 outcome=applied changes=3"}
        )

      assert eventually(fn ->
               version(appliance, 2) |> ConfigurationVersion.state() == :committed
             end)

      # The appliance closes on a commit, which is the protocol's way of forcing
      # the confirmation onto a connection it establishes afterwards.
      :ok = :ssl.close(socket)
      assert eventually(fn -> Appliances.status(reload(appliance)) == :offline end)
      assert Appliances.awaiting_confirmation(appliance.device_id).generation == 2

      # The fresh connection, and the confirmation on it.
      assert {:ok, second} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(second)
      :ok = send_frame(second, {:hello, :appliance})

      assert {:ok, {:down_commit_confirm, 2}} = read_frame(second, true)

      # The protocol has no acknowledgement of its own for a confirmation, so the
      # result frame is the only place the fact exists — and until it arrives the
      # row still says a commit is awaiting one.
      assert version(appliance, 2) |> ConfigurationVersion.state() == :committed

      :ok =
        send_frame(
          second,
          {:up_config_validate_result, "generation=2 outcome=confirmed changes=0"}
        )

      assert eventually(fn ->
               version(appliance, 2) |> ConfigurationVersion.state() == :confirmed
             end)

      assert Appliances.awaiting_confirmation(appliance.device_id) == nil
      :ok = :ssl.close(second)
    end

    test "a commit the appliance puts back is not recorded as one", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, actor: actor, certificate: certificate, key: key} = appliance_with()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      :ok = send_frame(socket, {:hello, :appliance})
      assert eventually(fn -> Appliances.status(reload(appliance)) == :online end)

      assert {:ok, _staged} =
               Appliances.stage_configuration(reload(appliance), amended_document(), actor)

      assert {:ok, {:down_config_stage, _document}} = read_frame(socket, true)

      :ok =
        send_frame(
          socket,
          {:up_config_validate_result, "generation=2 outcome=staged changes=3"}
        )

      assert {:ok, {:down_config_commit, 2, _deadline}} = read_frame(socket, true)

      # The appliance committed it and put it back, because its own medium would
      # not hold the version. That is not a commit, however briefly it was in
      # force: recording one would leave this server confirming a provisional
      # commit the appliance no longer has, and reporting a version as running that
      # the next boot would silently drop.
      :ok =
        send_frame(
          socket,
          {:up_config_validate_result, "generation=1 outcome=reverted changes=3"}
        )

      # Nothing to confirm, and the version stays where the staging left it.
      assert eventually(fn -> Appliances.awaiting_confirmation(appliance.device_id) == nil end)
      assert version(appliance, 2) |> ConfigurationVersion.state() == :staged
      assert version(appliance, 2).committed_at == nil
      :ok = :ssl.close(socket)
    end

    test "a refusal in the history sends the appliance's generation and records this server's",
         %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, actor: actor, certificate: certificate, key: key} = appliance_with()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      :ok = send_frame(socket, {:hello, :appliance})
      assert eventually(fn -> Appliances.status(reload(appliance)) == :online end)

      # First a document the appliance refuses. It advances THIS server's version
      # counter to 2 and leaves the appliance's where it was, which is the whole
      # setup: from here on the two numbers differ, and every later step has to
      # say which of them it means.
      assert {:ok, _refused} =
               Appliances.stage_configuration(reload(appliance), amended_document(), actor)

      assert {:ok, {:down_config_stage, _}} = read_frame(socket, true)

      :ok =
        send_frame(
          socket,
          {:up_config_validate_result,
           "generation=1 outcome=refused rejected=unknown-element offset=41"}
        )

      assert eventually(fn ->
               version(appliance, 2) |> ConfigurationVersion.state() == :refused
             end)

      # Then one it takes. This server calls it generation 3; the appliance, whose
      # counter never moved for the refusal, calls it its generation 2.
      assert {:ok, accepted} =
               Appliances.stage_configuration(
                 reload(appliance),
                 amended_document() <> "\n<!-- again -->",
                 actor
               )

      assert accepted.generation == 3
      assert {:ok, {:down_config_stage, _}} = read_frame(socket, true)

      :ok =
        send_frame(
          socket,
          {:up_config_validate_result, "generation=2 outcome=staged changes=1"}
        )

      # The frame carries the appliance's number, which is the only one its
      # datastore will commit.
      assert {:ok, {:down_config_commit, 2, _deadline}} = read_frame(socket, true)

      :ok =
        send_frame(
          socket,
          {:up_config_validate_result, "generation=2 outcome=applied changes=1"}
        )

      # And the row that moves is this server's version 3 — the document that was
      # actually taken. Version 2 stays refused: a commit recorded against it
      # would report a document the appliance rejected as the one in force.
      assert eventually(fn ->
               version(appliance, 3) |> ConfigurationVersion.state() == :committed
             end)

      assert version(appliance, 2) |> ConfigurationVersion.state() == :refused
      assert version(appliance, 2).committed_at == nil
      assert Appliances.awaiting_confirmation(appliance.device_id).generation == 3

      # The confirmation splits the same way: the appliance's number on the wire,
      # this server's on the row.
      :ok = :ssl.close(socket)
      assert eventually(fn -> Appliances.status(reload(appliance)) == :offline end)

      assert {:ok, second} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(second)
      :ok = send_frame(second, {:hello, :appliance})

      assert {:ok, {:down_commit_confirm, 2}} = read_frame(second, true)

      :ok =
        send_frame(
          second,
          {:up_config_validate_result, "generation=2 outcome=confirmed changes=0"}
        )

      assert eventually(fn ->
               version(appliance, 3) |> ConfigurationVersion.state() == :confirmed
             end)

      assert version(appliance, 2).confirmed_at == nil
      assert Appliances.awaiting_confirmation(appliance.device_id) == nil
      :ok = :ssl.close(second)
    end

    test "a document the appliance refuses is not committed", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, actor: actor, certificate: certificate, key: key} = appliance_with()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      :ok = send_frame(socket, {:hello, :appliance})
      assert eventually(fn -> Appliances.status(reload(appliance)) == :online end)

      assert {:ok, _staged} =
               Appliances.stage_configuration(reload(appliance), amended_document(), actor)

      assert {:ok, {:down_config_stage, _document}} = read_frame(socket, true)

      refusal = "generation=1 outcome=refused rejected=unknown-element offset=41"
      :ok = send_frame(socket, {:up_config_validate_result, refusal})

      assert eventually(fn ->
               version(appliance, 2) |> ConfigurationVersion.state() == :refused
             end)

      # The verdict is kept verbatim, because it names the rule and the offset an
      # operator has to go and fix.
      assert version(appliance, 2).validation_result == refusal
      # And nothing was committed, which is the whole assertion: a refused
      # document leaves the appliance on the generation it was already running.
      assert version(appliance, 2).committed_at == nil
      assert Appliances.awaiting_confirmation(appliance.device_id) == nil

      :ok = :ssl.close(socket)
    end

    test "a validate result nobody asked for moves nothing", %{anchor: anchor} do
      port = start_listener()
      %{appliance: appliance, certificate: certificate, key: key} = appliance_with()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, {:hello, {:server, 0, 0}}} = read_frame(socket)
      :ok = send_frame(socket, {:hello, :appliance})

      # A verdict for a generation this server never staged. It is a legal frame
      # from a semi-trusted peer, so it is dropped and counted rather than acted
      # on — a peer that could move a version's state by asserting a verdict would
      # be a peer that commits its own configuration.
      :ok =
        send_frame(socket, {:up_config_validate_result, "generation=9 outcome=staged changes=1"})

      # Nothing to read back: no commit follows, and the session stays up. The
      # upstream frame is what proves the session is still serving rather than a
      # wait on a clock.
      :ok = send_frame(socket, {:up_records, 1, "still talking"})
      assert eventually(fn -> reload(appliance).connected_since != nil end)

      assert Appliances.awaiting_confirmation(appliance.device_id) == nil
      assert version(appliance, 1) |> ConfigurationVersion.state() == :delivered

      :ok = :ssl.close(socket)
    end

    test "staging an appliance with no session is refused and still recorded" do
      _port = start_listener()
      %{appliance: appliance, actor: actor} = appliance_with()

      assert Appliances.stage_configuration(appliance, amended_document(), actor) ==
               {:error, :no_session}

      # The version and its audit record are durable: the change was authorised
      # and recorded, and the appliance was not there.
      assert version(appliance, 2) |> ConfigurationVersion.state() == :staging

      assert Enum.any?(
               Ctrld.Audit.list_events_for("appliance", appliance.device_id),
               &(&1.action == "configuration.staged")
             )
    end
  end

  describe "the listener's own refusals" do
    test "it will not start without an endpoint certificate to serve" do
      # Retire the one the setup issued, leaving the server nothing to offer.
      retired = DateTime.truncate(DateTime.utc_now(), :second)
      Repo.update_all(EndpointCertificate, set: [retired_at: retired])

      assert Listener.start_link(port: 0, name: :channel_listener_without_a_certificate) ==
               {:error, :no_endpoint_certificate}
    end

    test "it forgets a session no process can be holding" do
      %{appliance: appliance} = onboarded_fixture()
      {:ok, _appliance} = Appliances.session_opened(appliance, DateTime.utc_now())
      assert Appliances.status(reload(appliance)) == :online

      _port = start_listener()

      assert Appliances.status(reload(appliance)) == :offline
    end
  end

  describe "the ingest seam" do
    test "the deployed default is the counting one" do
      assert Ingest.configured() == Ctrld.Channel.Ingest.Counting
    end
  end

  # A listener on a port the operating system picks, under a name of this test's
  # own so nothing collides with the supervision tree's.
  defp start_listener do
    name = :"channel_listener_#{System.unique_integer([:positive])}"
    _listener = start_supervised!({Listener, port: 0, name: name})
    {:ok, {_address, port}} = Listener.listener_info(name)
    port
  end

  defp onboarded_appliance do
    %{appliance: appliance, key: key} = onboarded_fixture()
    %{appliance: appliance, certificate: appliance.certificate_der, key: key}
  end

  # The same, plus the administrator who onboarded it: the configuration tests
  # need an actor to stage as, and it must be the appliance's own so the audit
  # trail reads the way it would in a deployment.
  defp appliance_with do
    %{appliance: appliance, key: key, actor: actor} = onboarded_fixture()

    %{
      appliance: appliance,
      certificate: appliance.certificate_der,
      key: key,
      actor: actor
    }
  end

  # A second document, differing from the template so a staged generation is a
  # change rather than a resubmission. The comment is the difference: the
  # appliance's validator is what judges the content, and this end only has to
  # send bytes it will accept.
  defp amended_document do
    Ctrld.Configuration.template()
    |> String.replace("<rules>", "<rules>\n    <!-- amended -->", global: false)
  end

  defp version(appliance, generation) do
    Ctrld.Repo.get_by!(ConfigurationVersion,
      appliance_id: appliance.id,
      generation: generation
    )
  end

  # The groups are a parameter because the group is the whole subject of one
  # describe block above: everything else dials with the listener's own set,
  # while those tests name the set an appliance really offers.
  defp client_options(certificate, key, anchor, groups \\ Listener.supported_groups()) do
    [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      cacerts: [anchor],
      cert: certificate,
      key: {:ECPrivateKey, :public_key.der_encode(:ECPrivateKey, key)},
      versions: [:"tlsv1.3"],
      ciphers: Listener.cipher_suites(),
      supported_groups: groups,
      # An appliance dials an address literal, so it offers no server name. The
      # certificate is held to the address dialled instead, which is checked
      # explicitly above rather than by a name comparison that would prove
      # nothing here.
      server_name_indication: :disable
    ]
  end

  defp connect(port, certificate, key, anchor) do
    :ssl.connect(@loopback, port, client_options(certificate, key, anchor), 5_000)
  end

  defp attempt(port, certificate, key, anchor) do
    judge(connect(port, certificate, key, anchor))
  end

  # TLS 1.3 gives a client no message saying its certificate was accepted, so a
  # server that refuses one may do so after this end already has its keys. Both
  # shapes are the same outcome — no session — and a test that demanded one of
  # them would be asserting a detail of the runtime's handshake pacing.
  defp judge({:error, _reason}), do: :refused

  defp judge({:ok, socket}) do
    case :ssl.recv(socket, 0, 5_000) do
      {:error, _reason} ->
        :refused

      {:ok, _bytes} ->
        :ok = :ssl.close(socket)
        :admitted
    end
  end

  # `greeted?` is the decoder's own state, and it is a parameter rather than a
  # constant because a test reading a second down-frame is a test that has
  # already read the greeting. It defaults to "not yet", so every first read
  # asserts the rule the codec keeps — the server greets before it says anything
  # else — and only a read that follows one says otherwise.
  defp read_frame(socket, greeted? \\ false) do
    {:ok, header} = :ssl.recv(socket, Frame.header_length(), 5_000)
    {:ok, type, length} = Frame.read_header(header, :server, greeted?)

    payload =
      if length == 0 do
        <<>>
      else
        {:ok, payload} = :ssl.recv(socket, length, 5_000)
        payload
      end

    Frame.read_payload(type, :server, payload)
  end

  defp send_frame(socket, frame) do
    {:ok, bytes} = Frame.encode(:appliance, frame)
    :ssl.send(socket, bytes)
  end

  defp reload(appliance), do: Appliances.get_appliance_by_device_id(appliance.device_id)

  defp attach_ingest_telemetry do
    handler = :"ingest_#{System.unique_integer([:positive])}"
    test = self()

    :ok =
      :telemetry.attach(
        handler,
        Ctrld.Channel.Ingest.Counting.event(),
        fn _event, measurements, metadata, _config ->
          send(test, {:ingest, measurements, metadata})
        end,
        nil
      )

    handler
  end

  # The listener's connection process writes the row, and it is not this test's
  # process — so what is asserted is that the row arrives, within a bound.
  defp eventually(predicate, attempts \\ 150) do
    Enum.reduce_while(1..attempts, false, fn _attempt, _acc ->
      if predicate.() do
        {:halt, true}
      else
        Process.sleep(20)
        {:cont, false}
      end
    end)
  end
end
