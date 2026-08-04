defmodule Ctrld.PKIKeyCustodyTest do
  # Not async: this replaces the configured key-encryption key, which every
  # other test that seals or opens anything reads.
  use Ctrld.DataCase, async: false

  alias Ctrld.PKI
  alias Ctrld.Vault

  describe "unsealing under the wrong key" do
    test "refuses rather than continuing as though it could still sign" do
      authority = authority_fixture()
      configured = Application.get_env(:ctrld, Vault)
      on_exit(fn -> Application.put_env(:ctrld, Vault, configured) end)

      Application.put_env(:ctrld, Vault, key_base64: Base.encode64(:crypto.strong_rand_bytes(32)))

      assert_raise RuntimeError, ~r/does not open/, fn ->
        PKI.unseal_authority_key!(authority)
      end
    end
  end
end
