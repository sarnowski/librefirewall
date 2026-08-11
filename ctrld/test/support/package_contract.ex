defmodule Ctrld.PackageContract do
  @moduledoc """
  An independent, strict reader for the onboarding package.

  This is a test instrument and lives nowhere else on purpose: the server
  never reads a package, the appliance does, and a reader in the server's own
  tree would be production code with no caller. What it is *for* is the thing
  the format most needs — the writer and the reader are two implementations of
  one contract in two languages in two components, and two implementations of
  one format drift silently. So this one is written from the format's rules
  rather than from the writer's code, and it refuses everything the appliance's
  reader refuses: anything but ustar, anything but a regular file, any name
  that is not one of the four exactly, any size field that disagrees with the
  bytes present, any header whose checksum does not verify, and anything over
  a bound.

  A change to the writer that this reader still accepts is a change that stayed
  inside the contract. A change it rejects is the drift caught at the moment it
  is introduced.
  """

  @block 512

  @names ~w(device-certificate.pem trust-anchor.pem management-endpoint configuration.xml)

  @bounds %{
    "device-certificate.pem" => 16 * 1024,
    "trust-anchor.pem" => 16 * 1024,
    "management-endpoint" => 32,
    "configuration.xml" => 64 * 1024
  }

  @archive_bound 128 * 1024

  @doc """
  Decode an archive, or say which rule it broke.

  Returns the four members as a map from name to body.
  """
  @spec decode(binary()) :: {:ok, %{String.t() => binary()}} | {:error, term()}
  def decode(archive) when is_binary(archive) do
    with :ok <- check_archive_bound(archive),
         :ok <- check_block_multiple(archive),
         {:ok, members} <- walk(archive, %{}),
         :ok <- check_member_set(members) do
      {:ok, members}
    end
  end

  defp check_archive_bound(archive) do
    if byte_size(archive) > @archive_bound,
      do: {:error, {:archive_over_bound, byte_size(archive), @archive_bound}},
      else: :ok
  end

  defp check_block_multiple(archive) do
    if rem(byte_size(archive), @block) == 0,
      do: :ok,
      else: {:error, {:not_a_whole_number_of_blocks, byte_size(archive)}}
  end

  # Two consecutive zero blocks end the archive; nothing may follow them.
  defp walk(<<0::size(@block * 8), 0::size(@block * 8), rest::binary>>, members) do
    if zero?(rest), do: {:ok, members}, else: {:error, :bytes_after_end_of_archive}
  end

  defp walk(<<header::binary-size(@block), rest::binary>>, members) do
    with {:ok, name, size} <- read_header(header),
         :ok <- check_unique(members, name),
         {:ok, body, remainder} <- read_body(rest, size) do
      walk(remainder, Map.put(members, name, body))
    end
  end

  defp walk(<<>>, _members), do: {:error, :archive_ends_without_two_zero_blocks}
  defp walk(_short, _members), do: {:error, :truncated_header}

  defp read_header(header) do
    <<name::binary-size(100), _mode::binary-size(8), _uid::binary-size(8), _gid::binary-size(8),
      size::binary-size(12), _mtime::binary-size(12), checksum::binary-size(8),
      typeflag::binary-size(1), linkname::binary-size(100), magic::binary-size(6),
      version::binary-size(2), _uname::binary-size(32), _gname::binary-size(32),
      _devmajor::binary-size(8), _devminor::binary-size(8), prefix::binary-size(155),
      _pad::binary-size(12)>> = header

    with :ok <- check_magic(magic, version),
         :ok <- check_checksum(header, checksum),
         :ok <- check_typeflag(typeflag),
         :ok <- check_empty(linkname, :linkname),
         :ok <- check_empty(prefix, :prefix),
         {:ok, name} <- check_name(name),
         {:ok, size} <- read_octal(size),
         :ok <- check_member_bound(name, size) do
      {:ok, name, size}
    end
  end

  defp check_magic("ustar" <> <<0>>, "00"), do: :ok
  defp check_magic(magic, version), do: {:error, {:not_ustar, magic, version}}

  # The checksum is over the header with its own field read as eight spaces.
  defp check_checksum(header, field) do
    <<before::binary-size(148), _own::binary-size(8), rest::binary>> = header

    computed =
      (before <> String.duplicate(" ", 8) <> rest)
      |> :binary.bin_to_list()
      |> Enum.sum()

    case read_octal(field) do
      {:ok, ^computed} -> :ok
      {:ok, stated} -> {:error, {:checksum_mismatch, stated, computed}}
      {:error, reason} -> {:error, reason}
    end
  end

  # `0` and the historical NUL are a regular file. Every other type flag is a
  # link, a directory, a device, or a PAX or GNU extension header, and the
  # contract admits none of them.
  defp check_typeflag("0"), do: :ok
  defp check_typeflag(<<0>>), do: :ok
  defp check_typeflag(other), do: {:error, {:not_a_regular_file, other}}

  defp check_empty(field, which) do
    if zero?(field), do: :ok, else: {:error, {:unexpected_field, which}}
  end

  defp check_name(field) do
    name = trim_nul(field)

    cond do
      name not in @names -> {:error, {:unknown_member, name}}
      String.contains?(name, "/") -> {:error, {:member_name_carries_a_path, name}}
      true -> {:ok, name}
    end
  end

  defp check_member_bound(name, size) do
    bound = Map.fetch!(@bounds, name)
    if size > bound, do: {:error, {:member_over_bound, name, size, bound}}, else: :ok
  end

  defp check_unique(members, name) do
    if Map.has_key?(members, name), do: {:error, {:duplicate_member, name}}, else: :ok
  end

  defp read_body(rest, size) do
    padded = padded_length(size)

    case rest do
      <<body::binary-size(^size), padding::binary-size(^padded - ^size), remainder::binary>> ->
        if zero?(padding),
          do: {:ok, body, remainder},
          else: {:error, :member_padding_is_not_zero}

      _short ->
        {:error, {:member_body_shorter_than_its_size_field, size}}
    end
  end

  defp padded_length(size) do
    case rem(size, @block) do
      0 -> size
      remainder -> size + (@block - remainder)
    end
  end

  defp check_member_set(members) do
    missing = @names -- Map.keys(members)
    if missing == [], do: :ok, else: {:error, {:missing_members, missing}}
  end

  defp read_octal(field) do
    digits = field |> trim_nul() |> String.trim()

    cond do
      digits == "" ->
        {:error, :empty_numeric_field}

      not Regex.match?(~r/^[0-7]+$/, digits) ->
        {:error, {:not_octal, digits}}

      true ->
        {:ok, String.to_integer(digits, 8)}
    end
  end

  defp trim_nul(field), do: field |> :binary.split(<<0>>) |> hd()

  defp zero?(binary), do: binary |> :binary.bin_to_list() |> Enum.all?(&(&1 == 0))

  @doc "The four names the archive must carry, for a test to assert against."
  def names, do: @names

  @doc "The bound on one member, for a test to assert against."
  def bound(name), do: Map.fetch!(@bounds, name)

  @doc "The bound on the whole archive, for a test to assert against."
  def archive_bound, do: @archive_bound
end
