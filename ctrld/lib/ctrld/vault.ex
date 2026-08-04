defmodule Ctrld.Vault do
  @moduledoc """
  Envelope encryption for the private keys the server holds.

  The server is the device-issuing certificate authority, so it holds signing
  keys, and it will hold more of them over time. They live in Postgres
  encrypted under a key the deployment supplies in the environment: a database
  backup is then not a key escrow, and the key never rests beside the data it
  protects.

  The construction is AES-256-GCM from Erlang's `:crypto` — a fresh 96-bit
  initialisation vector per record, the tag kept beside the ciphertext, and
  associated data naming what the record *is*. The associated data is what
  makes a ciphertext non-portable: a private key lifted out of one row and
  written into another decrypts to nothing, because the context it was sealed
  under no longer matches.

  Nothing here logs, inspects, or renders a key or a plaintext. The struct
  this module returns carries ciphertext only, and the key itself never leaves
  the process that asked for it.
  """

  defmodule KeyError do
    @moduledoc """
    Raised when the key-encryption key is absent or malformed.

    The server refuses to boot on this rather than starting without the
    ability to read the keys it already holds — an unreadable authority is a
    fleet that cannot be onboarded to and does not know it yet.
    """
    defexception [:message]
  end

  @key_bytes 32
  @iv_bytes 12
  @cipher :aes_256_gcm
  @tag_bytes 16

  @typedoc "A sealed record: ciphertext, its initialisation vector, and its tag."
  @type sealed :: %{ciphertext: binary(), iv: binary(), tag: binary()}

  @doc """
  Decode a base64 key-encryption key, or say precisely why it is unusable.

  Pure, so the boot-time refusal and the suite exercise the same decision.
  """
  @spec decode_key(String.t() | nil) ::
          {:ok, binary()} | {:error, :absent | :not_base64 | {:wrong_length, pos_integer()}}
  def decode_key(nil), do: {:error, :absent}

  def decode_key(value) when is_binary(value) do
    case String.trim(value) do
      "" ->
        {:error, :absent}

      trimmed ->
        case Base.decode64(trimmed) do
          {:ok, <<key::binary-size(@key_bytes)>>} -> {:ok, key}
          {:ok, other} -> {:error, {:wrong_length, byte_size(other)}}
          :error -> {:error, :not_base64}
        end
    end
  end

  @doc """
  The configured key-encryption key, or a refusal to continue without one.

  Raises `Ctrld.Vault.KeyError`; the application's start calls this so a
  deployment with no key fails at boot rather than at the first issuance.
  """
  @spec key!() :: binary()
  def key! do
    configured = Application.get_env(:ctrld, __MODULE__, [])[:key_base64]

    case decode_key(configured) do
      {:ok, key} ->
        key

      {:error, reason} ->
        raise KeyError, message: "CTRLD_KEY_ENCRYPTION_KEY " <> explain(reason)
    end
  end

  defp explain(:absent),
    do: "is not set. It must carry 32 random bytes, base64 encoded."

  defp explain(:not_base64),
    do: "is not valid base64. It must carry 32 random bytes, base64 encoded."

  defp explain({:wrong_length, size}),
    do: "decodes to #{size} bytes; AES-256 needs exactly #{@key_bytes}."

  @doc """
  Seal a plaintext under the configured key, bound to `context`.

  `context` travels as GCM associated data and is not stored: it is recomputed
  from the row on the way back, so a ciphertext only opens where it belongs.
  """
  @spec seal(binary(), binary()) :: sealed()
  def seal(plaintext, context) when is_binary(plaintext) and is_binary(context) do
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(@cipher, key!(), iv, plaintext, context, @tag_bytes, true)

    %{ciphertext: ciphertext, iv: iv, tag: tag}
  end

  @doc """
  Open a sealed record bound to `context`.

  Returns `:error` — never a partial plaintext and never a raised value
  carrying one — when the key, the context, or any of the three stored fields
  does not match what sealed it.
  """
  @spec open(sealed(), binary()) :: {:ok, binary()} | :error
  def open(%{ciphertext: ciphertext, iv: iv, tag: tag}, context)
      when is_binary(ciphertext) and is_binary(iv) and is_binary(tag) and is_binary(context) do
    if byte_size(iv) == @iv_bytes and byte_size(tag) == @tag_bytes do
      case :crypto.crypto_one_time_aead(@cipher, key!(), iv, ciphertext, context, tag, false) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        :error -> :error
      end
    else
      :error
    end
  end
end
