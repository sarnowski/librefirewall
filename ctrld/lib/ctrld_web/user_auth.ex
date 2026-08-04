defmodule CtrldWeb.UserAuth do
  @moduledoc """
  Session-based authentication for the web interface.

  The cookie carries a random token and the database stores its digest, so the
  session is revocable from the server's side and a database read hands out no
  live session.

  Every page but the sign-in page requires an account. There is no anonymous
  read of the inventory, the audit trail, or the authority: this interface is
  where an appliance fleet is onboarded, and there is nothing on it that a
  stranger has business seeing.
  """

  use CtrldWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  alias Ctrld.Accounts

  @cookie "_ctrld_session"

  @doc "Start a session and send the administrator on."
  def sign_in(conn, user) do
    token = Accounts.create_session_token(user)

    conn
    |> renew_session()
    |> put_session(:user_token, token)
    |> put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
    |> redirect(to: signed_in_path(conn))
  end

  @doc "End the session, on the server as well as in the browser."
  def sign_out(conn) do
    token = get_session(conn, :user_token)
    token && Accounts.delete_session_token(token)

    if live_socket_id = get_session(conn, :live_socket_id) do
      CtrldWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
    |> renew_session()
    |> delete_resp_cookie(@cookie)
    |> redirect(to: ~p"/sign-in")
  end

  @doc "Put the signed-in account on the connection, or nothing."
  def fetch_current_user(conn, _options) do
    token = get_session(conn, :user_token)
    assign(conn, :current_user, token && Accounts.get_user_by_session_token(token))
  end

  @doc "Refuse a request from nobody."
  def require_authenticated_user(conn, _options) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "Sign in to continue.")
      |> redirect(to: ~p"/sign-in")
      |> halt()
    end
  end

  @doc "Send an already-signed-in administrator away from the sign-in page."
  def redirect_if_authenticated(conn, _options) do
    if conn.assigns[:current_user] do
      conn |> redirect(to: signed_in_path(conn)) |> halt()
    else
      conn
    end
  end

  @doc "The LiveView half of the same rule."
  def on_mount(:require_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:cont, socket}
    else
      {:halt,
       socket
       |> Phoenix.LiveView.put_flash(:error, "Sign in to continue.")
       |> Phoenix.LiveView.redirect(to: ~p"/sign-in")}
    end
  end

  def on_mount(:mount_current_user, _params, session, socket) do
    {:cont, mount_current_user(socket, session)}
  end

  defp mount_current_user(socket, session) do
    Phoenix.Component.assign_new(socket, :current_user, fn ->
      session["user_token"] && Accounts.get_user_by_session_token(session["user_token"])
    end)
  end

  @doc "Where an administrator lands after signing in."
  def signed_in_path(_conn), do: ~p"/appliances"

  # A fresh session on every sign-in and sign-out, so nothing an unauthenticated
  # visitor put in the session survives into an authenticated one.
  defp renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end
end
