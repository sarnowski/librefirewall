defmodule CtrldWeb.SessionController do
  @moduledoc """
  Starting and ending a session.

  A LiveView cannot write the session cookie, so the sign-in form posts here
  and this is where a session begins and ends.
  """

  use CtrldWeb, :controller

  alias Ctrld.{Accounts, Audit}
  alias CtrldWeb.UserAuth

  def create(conn, %{"user" => %{"email" => email, "password" => password}})
      when is_binary(email) and is_binary(password) do
    case Accounts.get_user_by_email_and_password(email, password) do
      nil ->
        conn
        |> put_flash(:error, "Those credentials do not match an account.")
        |> redirect(to: ~p"/sign-in")

      user ->
        Audit.write!(%{
          actor_id: user.id,
          actor_email: user.email,
          action: "session.started",
          subject_type: "user",
          subject_id: user.email,
          detail: %{}
        })

        UserAuth.sign_in(conn, user)
    end
  end

  def create(conn, _params) do
    conn
    |> put_flash(:error, "Those credentials do not match an account.")
    |> redirect(to: ~p"/sign-in")
  end

  def delete(conn, _params) do
    case conn.assigns[:current_user] do
      nil ->
        :ok

      user ->
        Audit.write!(%{
          actor_id: user.id,
          actor_email: user.email,
          action: "session.ended",
          subject_type: "user",
          subject_id: user.email,
          detail: %{}
        })
    end

    UserAuth.sign_out(conn)
  end
end
