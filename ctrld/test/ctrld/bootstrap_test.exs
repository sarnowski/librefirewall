defmodule Ctrld.BootstrapTest do
  # Not async: it replaces the bootstrap's configured credentials, which are
  # process-independent state.
  use Ctrld.DataCase, async: false

  alias Ctrld.{Accounts, Audit, Bootstrap, ChannelEndpoint, PKI}

  setup do
    configured = Application.get_env(:ctrld, Bootstrap, [])
    on_exit(fn -> Application.put_env(:ctrld, Bootstrap, configured) end)

    Application.put_env(:ctrld, Bootstrap,
      run_on_start: false,
      administrator_email: "first@librefirewall.invalid",
      administrator_password: "a-long-enough-password"
    )

    :ok
  end

  test "an empty database gets an administrator, an authority, and an endpoint certificate" do
    assert {:ok, taken} = Bootstrap.run()
    assert Enum.sort(taken) == [:administrator, :certificate_authority, :endpoint_certificate]

    assert Accounts.get_user_by_email("first@librefirewall.invalid").role == "administrator"
    assert PKI.active_authority()

    assert PKI.active_endpoint_certificate().endpoint ==
             ChannelEndpoint.to_string(ChannelEndpoint.configured!())
  end

  test "running it again takes no action at all" do
    assert {:ok, _} = Bootstrap.run()
    assert Bootstrap.run() == {:ok, []}
    assert Accounts.count_users() == 1
  end

  test "the account it created is recorded in the audit trail" do
    assert {:ok, _} = Bootstrap.run()

    assert [event] = Audit.list_events_for("user", "first@librefirewall.invalid")
    assert event.action == "user.bootstrapped"
  end

  test "the administrator can sign in with the password from the environment" do
    assert {:ok, _} = Bootstrap.run()

    assert Accounts.get_user_by_email_and_password(
             "first@librefirewall.invalid",
             "a-long-enough-password"
           )
  end

  test "an empty database with no credentials refuses rather than inventing any" do
    Application.put_env(:ctrld, Bootstrap,
      run_on_start: false,
      administrator_email: nil,
      administrator_password: nil
    )

    assert {:error, message} = Bootstrap.run()
    assert message =~ "CTRLD_ADMIN_EMAIL"
    assert Accounts.count_users() == 0
    refute PKI.active_authority()
  end

  test "an existing account means the credentials are not consulted at all" do
    existing = administrator_fixture()

    Application.put_env(:ctrld, Bootstrap,
      run_on_start: false,
      administrator_email: nil,
      administrator_password: nil
    )

    assert {:ok, taken} = Bootstrap.run()
    refute :administrator in taken
    assert Accounts.count_users() == 1
    assert Repo.get(Ctrld.Accounts.User, existing.id)
  end

  test "a moved endpoint retires the old certificate and issues one for the new address" do
    assert {:ok, _} = Bootstrap.run()
    first = PKI.active_endpoint_certificate()

    configured = Application.get_env(:ctrld, ChannelEndpoint)
    on_exit(fn -> Application.put_env(:ctrld, ChannelEndpoint, configured) end)
    Application.put_env(:ctrld, ChannelEndpoint, endpoint: "198.51.100.7:9443")

    assert {:ok, taken} = Bootstrap.run()
    assert :endpoint_certificate in taken

    second = PKI.active_endpoint_certificate()
    refute second.id == first.id
    assert second.endpoint == "198.51.100.7:9443"
  end

  test "run_on_start? reflects the configuration" do
    Application.put_env(:ctrld, Bootstrap, run_on_start: true)
    assert Bootstrap.run_on_start?()

    Application.put_env(:ctrld, Bootstrap, run_on_start: false)
    refute Bootstrap.run_on_start?()
  end
end
