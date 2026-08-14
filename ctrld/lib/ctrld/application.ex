defmodule Ctrld.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Fail closed, before anything else. Without the key-encryption key this
    # server can neither read the authority it already holds nor seal a new
    # one, and a server that starts anyway would discover that at the first
    # issuance — with an administrator waiting on it.
    _ = Ctrld.Vault.key!()

    children =
      [
        CtrldWeb.Telemetry,
        Ctrld.Repo,
        {DNSCluster, query: Application.get_env(:ctrld, :dns_cluster_query) || :ignore},
        {Phoenix.PubSub, name: Ctrld.PubSub},
        # The directory an operator's staging reaches a live session through. Up
        # before the listener and unconditionally, for the reason the ingest's
        # registry below is: a session registers as it opens, so the registry has
        # to exist before anything can accept a connection — and in test, where no
        # listener starts here, the suite starts its own and needs the registry
        # just the same.
        Ctrld.Channel.Sessions
      ] ++
        Ctrld.Channel.Ingest.Telemetry.children() ++
        bootstrap_child() ++
        channel_listener_child() ++
        [CtrldWeb.Endpoint]

    opts = [strategy: :one_for_one, name: Ctrld.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # The registry and dynamic supervisor an ingest holds its per-ring decoders
  # under go up before the listener, and unconditionally: which implementation
  # sits behind the ingest seam is configuration, and a supervisor started only
  # for one of them would make the seam's own choice a boot-order question.
  # They are two idle processes where the configured ingest keeps no state.

  # The first start's setup sits between the repository and the listener, and
  # is allowed to take the whole boot down with it: a server with no
  # administrator and no authority is one nobody can onboard through, and it
  # should say so at start rather than at first use — before it is listening.
  defp bootstrap_child do
    if Ctrld.Bootstrap.run_on_start?(), do: [Ctrld.Bootstrap], else: []
  end

  # After the bootstrap, because the certificate the listener serves is one of
  # the things the bootstrap puts in place, and before the web endpoint, because
  # an appliance's channel is the product and an administrator's browser is how
  # it is watched. A deployment that cannot listen does not start: an appliance
  # has nowhere else to report, and a server answering the web port while no
  # appliance can reach it is a server that looks healthy.
  #
  # Off in test, where the suite starts a listener of its own on a port the
  # operating system picks — the configured endpoint is an address literal a
  # fleet dials, and nothing in a gate container answers on it.
  defp channel_listener_child do
    if Application.get_env(:ctrld, Ctrld.Channel.Listener, [])[:listen] == true,
      do: [Ctrld.Channel.Listener],
      else: []
  end

  @impl true
  def config_change(changed, _new, removed) do
    CtrldWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
