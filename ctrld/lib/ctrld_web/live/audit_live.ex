defmodule CtrldWeb.AuditLive do
  @moduledoc """
  The audit trail: every state-changing action, newest first.
  """

  use CtrldWeb, :live_view

  alias Ctrld.Audit

  @limit 200

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Audit")
     |> assign(:limit, @limit)
     |> stream(:events, Audit.list_events(@limit))}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user}>
      <div>
        <h1 class="text-xl font-semibold">Audit</h1>
        <p class="text-sm opacity-70">The most recent {@limit} actions, newest first.</p>
      </div>

      <table class="table table-sm">
        <thead>
          <tr>
            <th>When</th>
            <th>Who</th>
            <th>Action</th>
            <th>Subject</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody id="audit-events" phx-update="stream">
          <tr id="audit-empty" class="hidden only:table-row">
            <td colspan="5" class="text-sm opacity-60">Nothing has happened yet.</td>
          </tr>
          <tr :for={{dom_id, event} <- @streams.events} id={dom_id}>
            <td class="text-xs whitespace-nowrap">{event.inserted_at}</td>
            <td class="text-xs">{event.actor_email}</td>
            <td class="text-xs font-mono">{event.action}</td>
            <td class="text-xs font-mono">{event.subject_type}/{event.subject_id}</td>
            <td class="text-xs opacity-70">{detail(event.detail)}</td>
          </tr>
        </tbody>
      </table>
    </Layouts.app>
    """
  end

  defp detail(detail) when detail == %{}, do: ""

  defp detail(detail) do
    detail
    |> Enum.sort_by(fn {key, _value} -> key end)
    |> Enum.map_join(" ", fn {key, value} -> "#{key}=#{value}" end)
  end
end
