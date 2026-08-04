defmodule Ctrld.VaultTest do
  # Not async: two tests here replace the configured key-encryption key, which
  # is process-independent state every other test that seals anything reads.
  use ExUnit.Case, async: false

  alias Ctrld.Vault

  describe "decode_key/1" do
    test "accepts exactly 32 base64 bytes" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, ^key} = Vault.decode_key(Base.encode64(key))
    end

    test "tolerates surrounding whitespace, which an environment file adds" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, ^key} = Vault.decode_key("  " <> Base.encode64(key) <> "\n")
    end

    test "refuses an absent value" do
      assert Vault.decode_key(nil) == {:error, :absent}
      assert Vault.decode_key("") == {:error, :absent}
      assert Vault.decode_key("   \n") == {:error, :absent}
    end

    test "refuses a value that is not base64" do
      assert Vault.decode_key("not base64 at all!") == {:error, :not_base64}
    end

    test "refuses a key of any other length, and says which" do
      assert Vault.decode_key(Base.encode64(:crypto.strong_rand_bytes(16))) ==
               {:error, {:wrong_length, 16}}

      assert Vault.decode_key(Base.encode64(:crypto.strong_rand_bytes(64))) ==
               {:error, {:wrong_length, 64}}
    end
  end

  describe "key!/0" do
    test "returns the configured key" do
      assert byte_size(Vault.key!()) == 32
    end

    test "refuses to continue without one" do
      configured = Application.get_env(:ctrld, Vault)
      on_exit(fn -> Application.put_env(:ctrld, Vault, configured) end)

      Application.put_env(:ctrld, Vault, key_base64: nil)
      assert_raise Vault.KeyError, ~r/is not set/, &Vault.key!/0

      Application.put_env(:ctrld, Vault, key_base64: "nonsense!!")
      assert_raise Vault.KeyError, ~r/not valid base64/, &Vault.key!/0

      Application.put_env(:ctrld, Vault, key_base64: Base.encode64("short"))
      assert_raise Vault.KeyError, ~r/decodes to 5 bytes/, &Vault.key!/0
    end
  end

  describe "seal and open" do
    test "a sealed record opens under its own context" do
      sealed = Vault.seal("a private key", "ctrld:test")
      assert {:ok, "a private key"} = Vault.open(sealed, "ctrld:test")
    end

    test "the ciphertext is not the plaintext" do
      sealed = Vault.seal("a private key", "ctrld:test")
      refute sealed.ciphertext == "a private key"
      assert byte_size(sealed.iv) == 12
      assert byte_size(sealed.tag) == 16
    end

    test "two sealings of one plaintext differ, because the vector is fresh each time" do
      first = Vault.seal("same", "ctrld:test")
      second = Vault.seal("same", "ctrld:test")
      refute first.iv == second.iv
      refute first.ciphertext == second.ciphertext
    end

    test "a record does not open under another context" do
      sealed = Vault.seal("a private key", "ctrld:one")
      assert Vault.open(sealed, "ctrld:two") == :error
    end

    test "a tampered ciphertext does not open" do
      sealed = Vault.seal("a private key", "ctrld:test")
      <<first, rest::binary>> = sealed.ciphertext
      tampered = %{sealed | ciphertext: <<Bitwise.bxor(first, 1), rest::binary>>}
      assert Vault.open(tampered, "ctrld:test") == :error
    end

    test "a tampered tag does not open" do
      sealed = Vault.seal("a private key", "ctrld:test")
      <<first, rest::binary>> = sealed.tag
      tampered = %{sealed | tag: <<Bitwise.bxor(first, 1), rest::binary>>}
      assert Vault.open(tampered, "ctrld:test") == :error
    end

    test "a vector or tag of the wrong size is refused rather than passed to the cipher" do
      sealed = Vault.seal("a private key", "ctrld:test")
      assert Vault.open(%{sealed | iv: <<1, 2, 3>>}, "ctrld:test") == :error
      assert Vault.open(%{sealed | tag: <<1, 2, 3>>}, "ctrld:test") == :error
    end

    test "a record does not open under another key" do
      sealed = Vault.seal("a private key", "ctrld:test")
      configured = Application.get_env(:ctrld, Vault)
      on_exit(fn -> Application.put_env(:ctrld, Vault, configured) end)

      Application.put_env(:ctrld, Vault, key_base64: Base.encode64(:crypto.strong_rand_bytes(32)))

      assert Vault.open(sealed, "ctrld:test") == :error
    end
  end
end
