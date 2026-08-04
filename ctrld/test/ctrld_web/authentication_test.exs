defmodule CtrldWeb.AuthenticationTest do
  use CtrldWeb.ConnCase, async: true

  alias Ctrld.{Accounts, Audit}

  describe "the sign-in page" do
    test "renders a form", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/sign-in")
      assert has_element?(view, "#sign-in-form")
      assert has_element?(view, "#sign-in-submit")
    end
  end

  describe "signing in" do
    test "starts a session and lands on the inventory", %{conn: conn} do
      user = administrator_fixture()

      conn =
        post(conn, ~p"/sign-in", %{
          "user" => %{"email" => user.email, "password" => "a-long-enough-password"}
        })

      assert redirected_to(conn) == ~p"/appliances"
      assert get_session(conn, :user_token)
      assert Accounts.get_user_by_session_token(get_session(conn, :user_token)).id == user.id
    end

    test "records the sign-in", %{conn: conn} do
      user = administrator_fixture()

      post(conn, ~p"/sign-in", %{
        "user" => %{"email" => user.email, "password" => "a-long-enough-password"}
      })

      assert [event] = Audit.list_events_for("user", user.email)
      assert event.action == "session.started"
    end

    test "refuses a wrong password without saying which half was wrong", %{conn: conn} do
      user = administrator_fixture()

      conn =
        post(conn, ~p"/sign-in", %{
          "user" => %{"email" => user.email, "password" => "the-wrong-password"}
        })

      assert redirected_to(conn) == ~p"/sign-in"
      refute get_session(conn, :user_token)
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "do not match"
    end

    test "refuses an address with no account, with the same words", %{conn: conn} do
      conn =
        post(conn, ~p"/sign-in", %{
          "user" => %{"email" => "nobody@example.invalid", "password" => "a-long-enough-password"}
        })

      assert redirected_to(conn) == ~p"/sign-in"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "do not match"
    end

    test "refuses a post that is not a credential pair at all", %{conn: conn} do
      conn = post(conn, ~p"/sign-in", %{"user" => %{"email" => "only"}})
      assert redirected_to(conn) == ~p"/sign-in"
      refute get_session(conn, :user_token)
    end
  end

  describe "signing out" do
    test "ends the session on the server, not just in the browser", %{conn: conn} do
      {conn, user, token} = sign_in_administrator(conn)
      assert Accounts.get_user_by_session_token(token)

      conn = delete(conn, ~p"/sign-out")

      assert redirected_to(conn) == ~p"/sign-in"
      refute Accounts.get_user_by_session_token(token)
      assert [_ended | _] = Audit.list_events_for("user", user.email)
    end
  end

  describe "pages that need an account" do
    for path <- ["/", "/appliances", "/appliances/onboard", "/authority", "/audit"] do
      test "#{path} sends a stranger to the sign-in page", %{conn: conn} do
        conn = get(conn, unquote(path))
        assert redirected_to(conn) == ~p"/sign-in"
      end
    end

    test "the package download sends a stranger to the sign-in page", %{conn: conn} do
      conn = get(conn, ~p"/appliances/#{String.duplicate("0", 32)}/package.tar")
      assert redirected_to(conn) == ~p"/sign-in"
    end

    test "an administrator reaches the inventory", %{conn: conn} do
      {conn, _user, _token} = sign_in_administrator(conn)
      {:ok, view, _html} = live(conn, ~p"/appliances")
      assert has_element?(view, "#onboard-link")
    end

    test "a signed-in administrator is sent away from the sign-in page", %{conn: conn} do
      {conn, _user, _token} = sign_in_administrator(conn)
      conn = get(conn, ~p"/sign-in")
      assert redirected_to(conn) == ~p"/appliances"
    end

    test "a session deleted on the server stops working", %{conn: conn} do
      {conn, _user, token} = sign_in_administrator(conn)
      Accounts.delete_session_token(token)

      conn = get(conn, ~p"/appliances")
      assert redirected_to(conn) == ~p"/sign-in"
    end
  end
end
