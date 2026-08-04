defmodule CtrldWeb.LoginLive do
  @moduledoc """
  The sign-in page.

  The form posts to a controller rather than to this LiveView, because a
  session cookie is written on a connection and a LiveView does not hold one.
  """

  use CtrldWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Sign in")
     |> assign(:form, to_form(%{"email" => "", "password" => ""}, as: :user))}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user}>
      <div class="mx-auto max-w-sm space-y-6">
        <div>
          <h1 class="text-xl font-semibold">Sign in</h1>
          <p class="text-sm opacity-70">
            The management server for a librefirewall fleet.
          </p>
        </div>

        <.form for={@form} id="sign-in-form" action={~p"/sign-in"} method="post" class="space-y-4">
          <.input field={@form[:email]} type="email" label="Address" autocomplete="username" required />
          <.input
            field={@form[:password]}
            type="password"
            label="Password"
            autocomplete="current-password"
            required
          />
          <.button id="sign-in-submit" class="btn btn-primary w-full">Sign in</.button>
        </.form>
      </div>
    </Layouts.app>
    """
  end
end
