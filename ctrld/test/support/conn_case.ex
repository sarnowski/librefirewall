defmodule CtrldWeb.ConnCase do
  @moduledoc """
  The case template for tests that drive the web interface.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint CtrldWeb.Endpoint

      use CtrldWeb, :verified_routes

      import Plug.Conn
      import Phoenix.ConnTest
      import Phoenix.LiveViewTest
      import CtrldWeb.ConnCase
      import Ctrld.Fixtures

      alias Ctrld.Repo
    end
  end

  setup tags do
    Ctrld.DataCase.setup_sandbox(tags)
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end

  @doc """
  Sign an administrator in on a connection.

  It goes through the real controller, so a test is exercising the session the
  interface actually issues rather than one a helper invented.
  """
  def sign_in(conn, user, password \\ "a-long-enough-password") do
    signed =
      Phoenix.ConnTest.dispatch(conn, CtrldWeb.Endpoint, :post, "/sign-in", %{
        "user" => %{"email" => user.email, "password" => password}
      })

    {Phoenix.ConnTest.recycle(signed), Plug.Conn.get_session(signed, :user_token)}
  end

  @doc """
  A connection already carrying an administrator's session.

  The token comes back too, because a recycled connection has no fetched
  session to read it out of and a test that wants to end the session from the
  server's side needs it.
  """
  def sign_in_administrator(conn) do
    user = Ctrld.Fixtures.administrator_fixture()
    {conn, token} = sign_in(conn, user)
    {conn, user, token}
  end
end
