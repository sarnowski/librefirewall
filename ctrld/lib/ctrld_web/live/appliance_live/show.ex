defmodule CtrldWeb.ApplianceLive.Show do
  @moduledoc """
  One appliance: its identity, what was issued to it, the configuration it was
  given, and what has been done to it.

  It is also where a configuration is changed. An administrator submits a
  document, this view asks the appliance's live session to stage it, and every
  step the transaction takes afterwards arrives as an announcement on the
  appliance's own topic rather than as a poll — so the verdict, the provisional
  commit and the confirmation that lands on the *next* connection each appear
  without a reload.

  The document is not edited in a field that starts empty: it starts as the
  generation the appliance is running, because a configuration change is an edit
  of what is there and a blank box invites a document with three sections missing.
  """

  use CtrldWeb, :live_view

  alias Ctrld.Appliances.ConfigurationVersion
  alias Ctrld.{Appliances, Audit, Configuration}

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
        if connected?(socket), do: Appliances.subscribe(appliance.device_id)

        {:ok,
         socket
         |> assign(:page_title, appliance.name)
         |> assign(:appliance, appliance)
         |> assign(:document, newest_document(appliance))
         |> assign(:events, Audit.list_events_for("appliance", appliance.device_id))}
    end
  end

  @impl true
  def handle_event("stage", %{"document" => document}, socket) when is_binary(document) do
    appliance = socket.assigns.appliance

    case Appliances.stage_configuration(appliance, document, socket.assigns.current_user) do
      {:ok, version} ->
        {:noreply,
         socket
         |> put_flash(
           :info,
           "Generation #{version.generation} staged; waiting for the appliance's verdict."
         )
         |> assign(:document, document)
         |> reload()}

      # Two refusals with quite different remedies, and both are the operator's to
      # act on: one is a document to fix, the other is an appliance to wait for. So
      # the submitted bytes stay in the box either way — a refusal that emptied the
      # field would be a refusal that lost the edit.
      {:error, reason} ->
        {:noreply,
         socket
         |> put_flash(:error, describe(reason))
         |> assign(:document, document)
         |> reload()}
    end
  end

  # A step of a configuration transaction. The row is re-read rather than patched
  # from the message: the message carries a transition and the row carries the
  # facts, and re-reading is what keeps this view showing the trail rather than its
  # own idea of it.
  @impl true
  def handle_info({:appliance_configuration, _device_id, _generation, _state}, socket) do
    {:noreply, reload(socket)}
  end

  # The two connection transitions, which change the answer to "can this appliance
  # be staged on at all".
  @impl true
  def handle_info({transition, _device_id, _at}, socket)
      when transition in [:appliance_connected, :appliance_disconnected] do
    {:noreply, reload(socket)}
  end

  # Recording bytes arriving. This page shows no traffic, so there is nothing to
  # re-render for one — and the clause is here rather than absent because an
  # unmatched message in a LiveView is a crash.
  @impl true
  def handle_info({:appliance_telemetry, _device_id, _ring, _position, _bytes}, socket) do
    {:noreply, socket}
  end

  defp reload(socket) do
    appliance = Appliances.get_appliance(socket.assigns.appliance.id)

    socket
    |> assign(:appliance, appliance)
    |> assign(:events, Audit.list_events_for("appliance", appliance.device_id))
  end

  defp newest_document(appliance) do
    case appliance.configuration_versions do
      [%{document: document} | _older] -> document
      [] -> Configuration.template()
    end
  end

  defp describe({:error, reason}), do: describe(reason)

  defp describe(reason) when reason in [:no_session, :in_flight],
    do: Appliances.describe(reason)

  defp describe(%Ecto.Changeset{}),
    do: "the version could not be recorded; nothing was sent to the appliance"

  defp describe(reason), do: Configuration.describe(reason)

  # What an operator is told about their chances before they press it. Read off
  # the same two facts the refusals are: a session has to be open, and no other
  # change may be in flight. Stated rather than used to disable the button — the
  # session can go away between the render and the submit, so the refusal is the
  # real answer and this is the courtesy.
  defp availability(appliance) do
    cond do
      Appliances.status(appliance) != :online ->
        "no session is open, so there is nothing to stage on"

      awaiting = Appliances.awaiting_confirmation(appliance.device_id) ->
        "generation #{awaiting.generation} is awaiting its confirmation"

      true ->
        "the appliance has a session open"
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
        <h2 class="font-semibold mb-3">Change the configuration</h2>
        <form phx-submit="stage" class="space-y-2">
          <.input
            type="textarea"
            id="configuration-document"
            name="document"
            value={@document}
            label="The document to stage, as the next generation"
            rows="16"
            class="w-full textarea font-mono text-xs"
          />
          <div class="flex items-center gap-3">
            <button id="stage-configuration" type="submit" class="btn btn-primary btn-sm">
              Stage and commit
            </button>
            <span id="stage-availability" class="text-xs opacity-70">
              {availability(@appliance)}
            </span>
          </div>
        </form>
        <p class="text-xs opacity-60 mt-2">
          Staging sends the document to the appliance, which validates it and answers. A document
          it accepts is committed straight away — provisionally: the appliance closes the session
          on a commit and undoes it unless a confirmation reaches it over a fresh connection, which
          this server sends as soon as the appliance dials back in. So a change to an appliance
          that cannot reach this server again reverts on its own, and that is the point.
        </p>
      </section>

      <section class="rounded-lg border border-base-300 p-4">
        <h2 class="font-semibold mb-3">Configuration history</h2>
        <div :for={version <- @appliance.configuration_versions} class="space-y-2 mb-4">
          <p class="text-sm">
            Generation {version.generation} ·
            <span id={"configuration-state-#{version.generation}"} class="font-semibold">
              {ConfigurationVersion.state(version)}
            </span>
            · <span class="font-mono text-xs">{version.document_sha256}</span>
          </p>
          <p
            :if={version.validation_result}
            id={"configuration-result-#{version.generation}"}
            class="font-mono text-xs opacity-80"
          >
            {version.validation_result}
          </p>
          <pre
            class="bg-base-200 rounded p-3 overflow-x-auto text-xs"
            phx-no-curly-interpolation
          ><code id={"configuration-#{version.generation}"}><%= version.document %></code></pre>
        </div>
        <p class="text-xs opacity-60 mt-2">
          Generation 1 is the document the onboarding package carried, which is why it shows as
          delivered rather than confirmed: it never travelled the channel. Every later generation
          did, and its state is read off the instants recorded for it rather than stored — a
          version that was committed and never confirmed says exactly that, because a rollback
          happens on the appliance's own deadline and reaches this server over no frame at all.
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
