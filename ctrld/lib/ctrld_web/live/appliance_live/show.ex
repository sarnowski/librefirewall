defmodule CtrldWeb.ApplianceLive.Show do
  @moduledoc """
  One appliance: its identity, what was issued to it, the configuration it was
  given, and what has been done to it.
  """

  use CtrldWeb, :live_view

  alias Ctrld.{Appliances, Audit}

  @impl true
  def mount(%{"device_id" => device_id}, _session, socket) do
    case Appliances.get_appliance_by_device_id(device_id) do
      nil ->
        {:ok,
         socket
         |> put_flash(:error, "No appliance with that device identifier.")
         |> push_navigate(to: ~p"/appliances")}

      appliance ->
        appliance = Appliances.get_appliance(appliance.id)

        {:ok,
         socket
         |> assign(:page_title, appliance.name)
         |> assign(:appliance, appliance)
         |> assign(:events, Audit.list_events_for("appliance", appliance.device_id))}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user}>
      <div class="flex items-baseline justify-between">
        <div>
          <h1 id="appliance-name" class="text-xl font-semibold">{@appliance.name}</h1>
          <p class="text-sm opacity-70">
            {Appliances.status(@appliance)} · request received {@appliance.csr_received_at}
          </p>
        </div>
        <a
          id="download-package"
          href={~p"/appliances/#{@appliance.device_id}/package.tar"}
          class="btn btn-primary btn-sm"
        >
          Download the package
        </a>
      </div>

      <section class="rounded-lg border border-base-300 p-4">
        <h2 class="font-semibold mb-3">Identity</h2>
        <dl class="grid grid-cols-[14rem_1fr] gap-y-2 text-sm">
          <dt class="opacity-70">Device identifier</dt>
          <dd id="appliance-device-id" class="font-mono">{@appliance.device_id}</dd>
          <dt class="opacity-70">SPKI fingerprint</dt>
          <dd id="appliance-fingerprint" class="font-mono break-all">
            {@appliance.spki_fingerprint}
          </dd>
          <dt class="opacity-70">Certificate serial</dt>
          <dd class="font-mono break-all">{@appliance.certificate_serial}</dd>
          <dt class="opacity-70">Issued</dt>
          <dd>{@appliance.certificate_issued_at}</dd>
          <dt class="opacity-70">Expires</dt>
          <dd>{@appliance.certificate_not_after}</dd>
          <dt class="opacity-70">Issued by</dt>
          <dd>{@appliance.certificate_authority.subject_common_name}</dd>
          <dt class="opacity-70">Key algorithm</dt>
          <dd>{@appliance.certificate_authority.key_algorithm}</dd>
          <dt class="opacity-70">Signature algorithm</dt>
          <dd>{@appliance.certificate_authority.signature_algorithm}</dd>
          <dt class="opacity-70">Endpoint it dials</dt>
          <dd class="font-mono">{@appliance.endpoint}</dd>
          <dt class="opacity-70">Channel</dt>
          <dd id="appliance-channel-status">{Appliances.status(@appliance)}</dd>
          <dt class="opacity-70">Session open since</dt>
          <dd id="appliance-connected-since">{@appliance.connected_since || "no session is open"}</dd>
          <dt class="opacity-70">Last seen</dt>
          <dd id="appliance-last-seen">{@appliance.last_seen_at || "never"}</dd>
          <dt class="opacity-70">Onboarded by</dt>
          <dd>{@appliance.onboarded_by && @appliance.onboarded_by.email}</dd>
        </dl>
      </section>

      <section class="rounded-lg border border-base-300 p-4">
        <h2 class="font-semibold mb-3">Configuration</h2>
        <div :for={version <- @appliance.configuration_versions} class="space-y-2">
          <p class="text-sm">
            Generation {version.generation} ·
            <span class="font-mono text-xs">{version.document_sha256}</span>
          </p>
          <pre
            class="bg-base-200 rounded p-3 overflow-x-auto text-xs"
            phx-no-curly-interpolation
          ><code id={"configuration-#{version.generation}"}><%= version.document %></code></pre>
        </div>
        <p class="text-xs opacity-60 mt-2">
          Generation 1 is the document the onboarding package carried. Further generations arrive
          over the management channel, whose configuration operations this server does not yet
          carry out — the channel comes up and carries the recordings upstream, and nothing on it
          stages or commits a document.
        </p>
      </section>

      <section class="rounded-lg border border-base-300 p-4">
        <h2 class="font-semibold mb-3">Audit</h2>
        <table class="table table-sm">
          <tbody>
            <tr :for={event <- @events} id={"event-#{event.id}"}>
              <td class="text-xs whitespace-nowrap">{event.inserted_at}</td>
              <td class="text-xs">{event.actor_email}</td>
              <td class="text-xs font-mono">{event.action}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </Layouts.app>
    """
  end
end
