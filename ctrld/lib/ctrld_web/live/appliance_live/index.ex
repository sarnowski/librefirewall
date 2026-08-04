defmodule CtrldWeb.ApplianceLive.Index do
  @moduledoc """
  The appliance inventory.

  The status column shows what this server can evidence and nothing else.
  Today that is "onboarded" and when the request arrived — the facts issuance
  left behind. There is no online, offline, or last-seen column, because
  nothing has yet established any of those and a column showing an unknown as
  a value is the one thing an inventory must never do.
  """

  use CtrldWeb, :live_view

  alias Ctrld.Appliances

  @impl true
  def mount(_params, _session, socket) do
    appliances = Appliances.list_appliances()

    {:ok,
     socket
     |> assign(:page_title, "Appliances")
     |> assign(:count, length(appliances))
     |> stream(:appliances, appliances)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user}>
      <div class="flex items-baseline justify-between">
        <div>
          <h1 class="text-xl font-semibold">Appliances</h1>
          <p class="text-sm opacity-70">{@count} onboarded</p>
        </div>
        <.link navigate={~p"/appliances/onboard"} id="onboard-link" class="btn btn-primary btn-sm">
          Onboard an appliance
        </.link>
      </div>

      <table class="table table-sm">
        <thead>
          <tr>
            <th>Name</th>
            <th>Device identifier</th>
            <th>Status</th>
            <th>Request received</th>
            <th>Endpoint</th>
          </tr>
        </thead>
        <tbody id="appliances" phx-update="stream">
          <tr id="appliances-empty" class="hidden only:table-row">
            <td colspan="5" class="text-sm opacity-60">
              No appliance has been onboarded yet.
            </td>
          </tr>
          <tr :for={{dom_id, appliance} <- @streams.appliances} id={dom_id}>
            <td>
              <.link navigate={~p"/appliances/#{appliance.device_id}"} class="link">
                {appliance.name}
              </.link>
            </td>
            <td class="font-mono text-xs">{appliance.device_id}</td>
            <td>
              <span class="badge badge-success badge-sm">
                {Appliances.status(appliance)}
              </span>
            </td>
            <td class="text-xs">{appliance.csr_received_at}</td>
            <td class="font-mono text-xs">{appliance.endpoint}</td>
          </tr>
        </tbody>
      </table>

      <p class="text-xs opacity-60">
        Whether an appliance is reachable is not shown, because nothing here knows: an appliance
        dials this server over the management channel, and that channel does not exist yet.
      </p>
    </Layouts.app>
    """
  end
end
