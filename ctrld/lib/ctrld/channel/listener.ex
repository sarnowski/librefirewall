defmodule Ctrld.Channel.Listener do
  @moduledoc """
  The port appliances dial, and the TLS session they dial into.

  One listener, separate from the web endpoint in every way that matters: its
  own port, its own certificate, its own trust decision, and a client
  certificate it will not do without. The web endpoint serves administrators over
  HTTP and knows nothing about this; nothing about this knows what a request is.

  ## What is served, and what is required

  The certificate is the channel endpoint certificate this server issued under
  its own authority, for the endpoint appliances were told to dial. It carries
  that address as a subject alternative name, because an appliance validates the
  certificate against the address literal it dialled and never against a name —
  there is no resolver between the two ends, so there is nothing between them to
  poison.

  A client certificate is **required and verified** against this server's own
  authority and nothing else. `verify_peer` with `fail_if_no_peer_cert` is the
  whole of it: a peer with no certificate, one signed by another authority, or
  one outside its validity window does not reach a connection process at all,
  and the identity the session then has is `Ctrld.Channel.Identity`'s to read off
  the certificate the handshake validated.

  ## The suite and the group

  Exactly one cipher suite is offered — `TLS_CHACHA20_POLY1305_SHA256` — and
  exactly one key-exchange group — the hybrid post-quantum `X25519MLKEM768` —
  and both are named rather than left to a default so that what a session
  negotiated is a fact of this module instead of an outcome to go and measure.
  Each is the one the contract fixes and the one the appliance's provider offers,
  so the intersection with an appliance is the whole of what either end has.

  **One group and not two, deliberately.** The appliance offers the hybrid and
  nothing beside it, and this end matches that rather than widening it: a
  classical group offered here as well would be one a peer that can reach the
  port is free to choose, and choosing it hands over the classical half alone and
  gives up the harvest-now-decrypt-later property the hybrid exchange exists for
  — on a channel that carries a customer's network history. A narrower
  intersection cannot be negotiated down, which is the reason to keep it narrow
  at both ends. The cost is that there is no fallback: a peer without the hybrid
  gets `insufficient security` and no session, which is the intended answer.

  The group needs both halves of the runtime beneath it. `:ssl` implements it
  from OTP 28, and `:crypto` takes ML-KEM from the OpenSSL it is linked against
  rather than implementing it — so where that OpenSSL predates 3.5 the group is
  absent from `:ssl.groups/0` and this listener does not start at all, refusing
  its options rather than quietly serving something weaker.

  ## Which address is bound

  The port is the configured endpoint's, and the address bound is every local
  one. The endpoint is what appliances dial — a public address, or one a NAT
  translates to this host — and binding it literally would refuse to start on
  every deployment that is not addressed on the internet by the same address its
  appliances reach it at.

  ## Adversary

  An **unauthenticated peer that can reach the port**, and behind the handshake a
  **semi-trusted appliance**. What bounds the first is the connection ceiling
  below and the handshake deadline in `Ctrld.Channel.Transport`; what bounds the
  second is every refusal in the session and the codec above it.
  """

  alias Ctrld.Channel.{Handler, Transport}
  alias Ctrld.{Appliances, ChannelEndpoint, PKI}
  alias Ctrld.PKI.EndpointCertificate

  require Logger

  # A fleet's worth of appliances and room to spare, and far below the transport
  # default: every connection is one appliance's one session, so a ceiling in the
  # thousands is a fleet bound rather than a throughput one — and it is the bound
  # on how much an unauthenticated peer can occupy, which is the reason to state
  # it rather than inherit it.
  @max_connections 4_096

  # How long a session may go without a byte from the appliance before it is
  # dropped. The contract's upstream flush cadence is at least once a second
  # whenever unsent bytes exist and the acknowledgement cadence answers it, so a
  # connection silent for this long is not a working channel — which is why the
  # protocol has no ping: the traffic is the liveness.
  @read_timeout :timer.seconds(90)

  @typedoc "What a listener may be started with; everything else is derived."
  @type option :: {:port, :inet.port_number()} | {:name, GenServer.name()}

  @doc """
  A supervised listener.

  Started with no options it binds the configured endpoint's port under this
  module's own name, which is what the supervision tree does. A test passes
  `port: 0` to be given one by the operating system and its own name to run
  beside another.
  """
  @spec child_spec([option()]) :: Supervisor.child_spec()
  def child_spec(options) do
    %{
      id: Keyword.get(options, :name, __MODULE__),
      start: {__MODULE__, :start_link, [options]},
      type: :supervisor,
      restart: :permanent
    }
  end

  @doc """
  Start listening.

  Refuses where there is nothing to serve: without the endpoint certificate this
  server issued there is no session to offer an appliance, and a listener that
  accepted connections in order to fail every handshake would be a port that
  looks answered. The bootstrap issues that certificate before this starts, so
  reaching the refusal means the certificate was retired without a replacement.
  """
  @spec start_link([option()]) :: Supervisor.on_start()
  def start_link(options) do
    certificate = PKI.active_endpoint_certificate()

    if is_nil(certificate) do
      {:error, :no_endpoint_certificate}
    else
      listen(certificate, options)
    end
  end

  @doc """
  The address and port a running listener is bound to.

  The port is what a test needs after asking for an ephemeral one; a deployment
  already knows it, having configured it.
  """
  @spec listener_info(GenServer.name() | pid()) ::
          {:ok, ThousandIsland.Transport.socket_info()} | :error
  def listener_info(listener \\ __MODULE__), do: ThousandIsland.listener_info(listener)

  @doc """
  The cipher suites this listener offers, which is one.

  Exposed so a test can hold a negotiated session to it rather than restate it.
  """
  @spec cipher_suites() :: [:ssl.erl_cipher_suite()]
  def cipher_suites do
    [%{key_exchange: :any, cipher: :chacha20_poly1305, mac: :aead, prf: :sha256}]
  end

  @doc "The key-exchange groups this listener offers, which is one."
  @spec supported_groups() :: [atom()]
  def supported_groups, do: [:x25519mlkem768]

  defp listen(certificate, options) do
    # A live session cannot outlive the process that held one, so every row
    # claiming one is stale before this listener accepts anything. Cleared here
    # rather than on a schedule because this is the only moment at which the
    # answer is knowable: no session exists yet.
    cleared = Appliances.clear_sessions()

    if cleared > 0 do
      Logger.info(
        "ctrld: cleared #{cleared} appliance session(s) left by a previous run of the channel listener"
      )
    end

    port = Keyword.get_lazy(options, :port, fn -> ChannelEndpoint.configured!().port end)
    name = Keyword.get(options, :name, __MODULE__)

    ThousandIsland.start_link(
      port: port,
      handler_module: Handler,
      transport_module: Transport,
      transport_options: transport_options(certificate),
      num_connections: @max_connections,
      read_timeout: @read_timeout,
      # The listener's own name, on its own supervisor. `genserver_options` is
      # not this: the acceptor passes that term to every *connection* process it
      # starts, so a name there is registered by whichever connection arrives
      # first and refused to the second — a channel that serves one appliance at
      # a time — while the thing a caller looks the listener up by stays
      # anonymous.
      supervisor_options: [name: name]
    )
  end

  defp transport_options(%EndpointCertificate{} = certificate) do
    key = PKI.unseal_endpoint_key!(certificate)

    [
      # Bound to every local address: what the endpoint names is where appliances
      # dial, which is not necessarily an address this host holds.
      ip: :any,
      cert: certificate.certificate_der,
      # The key never becomes a file and never leaves this list. It is unsealed
      # into the listener's own options and handed straight to the TLS
      # implementation, so nothing writes it anywhere a process without the
      # key-encryption key could read it.
      key: {:ECPrivateKey, :public_key.der_encode(:ECPrivateKey, key)},
      # The authority that signed every device certificate, and the only one a
      # client certificate may chain to. A system trust store here would admit
      # any appliance any public authority chose to name.
      cacerts: [certificate.certificate_authority.certificate_der],
      verify: :verify_peer,
      fail_if_no_peer_cert: true,
      versions: [:"tlsv1.3"],
      ciphers: cipher_suites(),
      supported_groups: supported_groups(),
      # There is no session resumption: a channel is one long session per
      # appliance, so a ticket would be state kept for a handshake that happens
      # once per reconnect and buys nothing.
      session_tickets: :disabled
    ]
  end
end
