defmodule CtrldWeb.InventoryLiveTest do
  use CtrldWeb.ConnCase, async: true

  alias Ctrld.Audit

  setup %{conn: conn} do
    {conn, user, _token} = sign_in_administrator(conn)
    _authority = authority_fixture()
    %{conn: conn, user: user}
  end

  describe "the inventory" do
    test "says so when there is nothing in it", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/appliances")
      assert render(view) =~ "No appliance has been onboarded yet"
    end

    test "lists an onboarded appliance with the status the server can evidence", %{conn: conn} do
      %{appliance: appliance} = onboarded_fixture(name: "the first one")

      {:ok, view, _html} = live(conn, ~p"/appliances")
      html = render(view)

      assert html =~ "the first one"
      assert html =~ appliance.device_id
      assert html =~ "onboarded"
    end

    test "shows no reachability, because nothing establishes it yet", %{conn: conn} do
      _onboarded = onboarded_fixture()
      {:ok, view, _html} = live(conn, ~p"/appliances")
      html = render(view)

      refute html =~ "Last seen"
      refute html =~ ">online<"
      refute html =~ ">offline<"
      assert html =~ "not shown"
    end

    test "the root path is the inventory", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")
      assert has_element?(view, "#onboard-link")
    end
  end

  describe "one appliance" do
    setup do
      %{appliance: appliance, actor: actor} = onboarded_fixture(name: "the detailed one")
      %{appliance: appliance, actor: actor}
    end

    test "shows the identity, the algorithms, and the endpoint", %{
      conn: conn,
      appliance: appliance
    } do
      {:ok, view, _html} = live(conn, ~p"/appliances/#{appliance.device_id}")

      assert view |> element("#appliance-device-id") |> render() =~ appliance.device_id
      assert view |> element("#appliance-fingerprint") |> render() =~ appliance.spki_fingerprint

      html = render(view)
      assert html =~ "ecdsa-p256"
      assert html =~ "ecdsa-with-sha256"
      assert html =~ appliance.endpoint
      assert html =~ appliance.certificate_serial
    end

    test "shows the configuration it was given, as generation 1", %{
      conn: conn,
      appliance: appliance
    } do
      {:ok, view, _html} = live(conn, ~p"/appliances/#{appliance.device_id}")
      assert has_element?(view, "#configuration-1")
    end

    test "shows the audit trail for that appliance", %{conn: conn, appliance: appliance} do
      [event] = Audit.list_events_for("appliance", appliance.device_id)
      {:ok, view, _html} = live(conn, ~p"/appliances/#{appliance.device_id}")
      assert has_element?(view, "#event-#{event.id}")
    end

    test "offers the package again", %{conn: conn, appliance: appliance} do
      {:ok, view, _html} = live(conn, ~p"/appliances/#{appliance.device_id}")
      assert has_element?(view, "#download-package")
    end

    test "an unknown device identifier goes back to the inventory", %{conn: conn} do
      assert {:error, {:live_redirect, %{to: "/appliances"}}} =
               live(conn, ~p"/appliances/#{String.duplicate("0", 32)}")
    end
  end

  describe "the authority page" do
    test "shows the authority and the endpoint certificate by their public facts", %{conn: conn} do
      _certificate = endpoint_certificate_fixture()
      {:ok, view, _html} = live(conn, ~p"/authority")

      assert has_element?(view, "#authority-fingerprint")
      assert has_element?(view, "#endpoint-certificate-endpoint")
    end

    test "never offers a private key", %{conn: conn} do
      _certificate = endpoint_certificate_fixture()
      {:ok, view, _html} = live(conn, ~p"/authority")
      html = render(view)

      refute html =~ "PRIVATE KEY"
      refute html =~ "sealed_key"
      refute html =~ "Export"
    end

    test "says plainly when there is no authority", %{conn: conn} do
      Ctrld.PKI.active_authority() |> Ctrld.Repo.delete!()
      {:ok, view, _html} = live(conn, ~p"/authority")
      assert render(view) =~ "holds no certificate authority"
    end
  end

  describe "the audit page" do
    test "says so when nothing has happened", %{conn: conn} do
      Ctrld.Repo.delete_all(Ctrld.Audit.Event)
      {:ok, view, _html} = live(conn, ~p"/audit")
      assert render(view) =~ "Nothing has happened yet"
    end

    test "shows an onboarding, its actor, and its detail", %{conn: conn, user: user} do
      %{appliance: appliance} = onboarded_fixture(actor: user)

      {:ok, view, _html} = live(conn, ~p"/audit")
      html = render(view)

      assert html =~ "appliance.onboarded"
      assert html =~ user.email
      assert html =~ appliance.device_id
    end

    test "shows a package download as its own action", %{conn: conn} do
      %{appliance: appliance} = onboarded_fixture()
      get(conn, ~p"/appliances/#{appliance.device_id}/package.tar")

      {:ok, view, _html} = live(conn, ~p"/audit")
      assert render(view) =~ "package.downloaded"
    end
  end
end
