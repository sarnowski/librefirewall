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

  The suite is not async: a listener binds a real port, and the sandbox
  connection has to be shared with the connection processes the listener spawns,
  which are not the test's own.
  """

  use Ctrld.DataCase, async: false

  alias Ctrld.Appliances
  alias Ctrld.Channel.{Frame, Handler, Ingest, Listener, Transport}
  alias Ctrld.PKI.EndpointCertificate

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
    test "TLS 1.3 with TLS_CHACHA20_POLY1305_SHA256 over x25519", %{anchor: anchor} do
      port = start_listener()
      %{certificate: certificate, key: key} = onboarded_appliance()

      assert {:ok, socket} = connect(port, certificate, key, anchor)
      assert {:ok, information} = :ssl.connection_information(socket)

      assert information[:protocol] == :"tlsv1.3"

      assert information[:selected_cipher_suite] == %{
               key_exchange: :any,
               cipher: :chacha20_poly1305,
               mac: :aead,
               prf: :sha256
             }

      # The group is a fact of the listener's own options rather than something to
      # go and measure: it offers exactly one, so this is the group every session
      # it accepts was established over.
      assert Listener.supported_groups() == [:x25519]
      assert Listener.cipher_suites() == [information[:selected_cipher_suite]]

      :ok = :ssl.close(socket)
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

  defp client_options(certificate, key, anchor) do
    [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      cacerts: [anchor],
      cert: certificate,
      key: {:ECPrivateKey, :public_key.der_encode(:ECPrivateKey, key)},
      versions: [:"tlsv1.3"],
      ciphers: Listener.cipher_suites(),
      supported_groups: Listener.supported_groups(),
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

  defp read_frame(socket) do
    {:ok, header} = :ssl.recv(socket, Frame.header_length(), 5_000)
    {:ok, type, length} = Frame.read_header(header, :server, false)

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
