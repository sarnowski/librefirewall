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
        {Phoenix.PubSub, name: Ctrld.PubSub}
      ] ++
        bootstrap_child() ++
        [CtrldWeb.Endpoint]

    opts = [strategy: :one_for_one, name: Ctrld.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # The first start's setup sits between the repository and the listener, and
  # is allowed to take the whole boot down with it: a server with no
  # administrator and no authority is one nobody can onboard through, and it
  # should say so at start rather than at first use — before it is listening.
  defp bootstrap_child do
    if Ctrld.Bootstrap.run_on_start?(), do: [Ctrld.Bootstrap], else: []
  end

  @impl true
  def config_change(changed, _new, removed) do
    CtrldWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
