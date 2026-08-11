defmodule Ctrld.Channel.Transport do
  @moduledoc """
  The TLS transport the channel listener runs on: the stock one, with the
  handshake on a clock.

  ## Why this module exists

  A connection process is committed the moment a peer completes a TCP handshake,
  and the TLS handshake that follows is the first thing it does. The stock
  transport waits for it without a deadline, so a peer that opens a connection
  and then says nothing — or dribbles half a client hello — holds a process for
  as long as it cares to. Enough of those and the listener has no room left for
  an appliance, which is the state-exhaustion attacker rather than a hypothetical:
  reaching this point costs an adversary a TCP handshake and no credential at
  all, the peer being unauthenticated until the very handshake it is refusing to
  finish.

  There is no server option for this. Erlang's TLS implementation takes the
  handshake deadline as an argument to the handshake call and not as a listen
  option, so bounding it means being the module that makes the call. That is
  what this is: the transport behaviour, one implementation of its own, and
  every other callback the stock TLS transport's.

  ## Adversary

  An **unauthenticated peer that can reach the channel port**, which is anyone
  who can route to it. It is refused rather than served, and the refusal costs
  it a connection slot for the deadline below and nothing after.
  """

  alias ThousandIsland.Transports.SSL

  @behaviour ThousandIsland.Transport

  # Generous against a real appliance on a slow link and short against a peer
  # holding a slot for free.
  @default_handshake_timeout :timer.seconds(15)

  @doc """
  How long a peer has to complete the TLS handshake.

  The deployment's value is the default; the suite shortens it, because a test
  that proves a stalled peer is dropped has to wait for the deadline to pass and
  waiting fifteen seconds for it would be paid on every run.
  """
  @spec handshake_timeout() :: pos_integer()
  def handshake_timeout do
    :ctrld
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(:handshake_timeout, @default_handshake_timeout)
  end

  @impl ThousandIsland.Transport
  @spec handshake(SSL.socket()) :: ThousandIsland.Transport.on_handshake()
  def handshake(socket) do
    case :ssl.handshake(socket, handshake_timeout()) do
      {:ok, socket} -> {:ok, socket}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl ThousandIsland.Transport
  defdelegate listen(port, options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate accept(listener_socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate upgrade(socket, options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate controlling_process(socket, pid), to: SSL

  @impl ThousandIsland.Transport
  defdelegate recv(socket, length, timeout), to: SSL

  @impl ThousandIsland.Transport
  defdelegate send(socket, data), to: SSL

  @impl ThousandIsland.Transport
  defdelegate sendfile(socket, filename, offset, length), to: SSL

  @impl ThousandIsland.Transport
  defdelegate getopts(socket, options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate setopts(socket, options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate shutdown(socket, way), to: SSL

  @impl ThousandIsland.Transport
  defdelegate close(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate sockname(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate peername(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate peercert(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate secure?(), to: SSL

  @impl ThousandIsland.Transport
  defdelegate getstat(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate negotiated_protocol(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate connection_information(socket), to: SSL
end
