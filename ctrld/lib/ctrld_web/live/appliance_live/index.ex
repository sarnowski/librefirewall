defmodule CtrldWeb.ApplianceLive.Index do
  @moduledoc """
  The appliance inventory.

  The status column shows what this server can evidence and nothing else: a
  session open on this server right now, a session that has ended with the
  instant it was last seen, or a certificate issued and no session ever — one
  of three facts, derived from the row and never stored. A column showing an
  unknown as a value is the one thing an inventory must never do, which is why
  an appliance that has never dialled reads as onboarded rather than as
  offline.

  The page is rendered from the rows as they are at mount. A session opening or
  closing is announced on `Ctrld.Appliances.fleet_topic/0`, and this view does
  not yet subscribe to it — so a status here is current as of the last load.
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
            <th>Last seen</th>
            <th>Request received</th>
            <th>Endpoint</th>
          </tr>
        </thead>
        <tbody id="appliances" phx-update="stream">
          <tr id="appliances-empty" class="hidden only:table-row">
            <td colspan="6" class="text-sm opacity-60">
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
              <span
                id={"appliance-status-#{appliance.device_id}"}
                class={["badge badge-sm", status_badge(Appliances.status(appliance))]}
              >
                {Appliances.status(appliance)}
              </span>
            </td>
            <td class="text-xs">{appliance.last_seen_at || "never"}</td>
            <td class="text-xs">{appliance.csr_received_at}</td>
            <td class="font-mono text-xs">{appliance.endpoint}</td>
          </tr>
        </tbody>
      </table>

      <p class="text-xs opacity-60">
        An appliance dials this server over the management channel and holds the connection open, so
        online means a session is open on this server at this moment. Offline means one has been and
        has ended; onboarded means a certificate was issued and no session has ever opened.
      </p>
    </Layouts.app>
    """
  end

  # Three statuses, three colours, and no fourth: a colour for a status the
  # derivation cannot produce would be a branch nothing can reach.
  defp status_badge(:online), do: "badge-success"
  defp status_badge(:offline), do: "badge-warning"
  defp status_badge(:onboarded), do: "badge-neutral"
end
