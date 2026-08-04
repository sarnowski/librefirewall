defmodule Ctrld.Package do
  @moduledoc """
  Composing the onboarding package: the one artifact this server produces and
  an appliance consumes.

  The archive is written here byte for byte rather than through a tar library,
  and that is deliberate. The appliance's reader accepts the narrowest tar
  that can carry four small files and refuses everything else by name — no PAX
  or GNU extension, no path prefix, no member but the four — so what matters
  is not that some tar tool can read what this writes but that *this* writer
  emits exactly the shape that reader admits. Four 512-byte headers are small
  enough to write directly and to assert on directly, and the suite decodes
  what comes out of here against every rule the format states. That decoding
  test is the mechanism that keeps two implementations of one format from
  drifting apart, since the two live in different languages in different
  components.

  The archive is not signed. It is authenticated by the session it travels in
  — the administrator opened it to the appliance after checking the
  appliance's fingerprint out of band — and a factory-fresh appliance trusts
  nobody, so there is no anchor a signature could be verified against.
  """

  @device_certificate "device-certificate.pem"
  @trust_anchor "trust-anchor.pem"
  @management_endpoint "management-endpoint"
  @configuration "configuration.xml"

  @member_bounds %{
    @device_certificate => 16 * 1024,
    @trust_anchor => 16 * 1024,
    @management_endpoint => 32,
    @configuration => 64 * 1024
  }

  @members [@device_certificate, @trust_anchor, @management_endpoint, @configuration]

  @archive_bound 128 * 1024

  @block 512
  @mode "0000644"

  @type contents :: %{
          device_certificate_pem: String.t(),
          trust_anchor_pem: String.t(),
          management_endpoint: String.t(),
          configuration_xml: String.t()
        }

  @type reason :: {:member_too_large, String.t(), pos_integer(), pos_integer()}

  @doc "The four member names, in the order this writer emits them."
  @spec members() :: [String.t()]
  def members, do: @members

  @doc "The size bound of one member, in bytes."
  @spec member_bound(String.t()) :: pos_integer()
  def member_bound(name), do: Map.fetch!(@member_bounds, name)

  @doc """
  The size bound of the whole archive, in bytes.

  There is no runtime check against it here, and that is not an omission: the
  four member bounds already imply it — the largest archive four members
  within their bounds can produce is well under this — so a check would be a
  branch nothing could ever reach. What holds the two bounds consistent is a
  test that composes the largest archive the member bounds permit and asserts
  it fits, which fails the moment a member bound rises past what this one
  allows.
  """
  @spec archive_bound() :: pos_integer()
  def archive_bound, do: @archive_bound

  @doc """
  Build the archive.

  `modified_at` is written into every header's modification time, so a package
  built twice from the same inputs is the same bytes — which is what lets the
  suite assert on them and an administrator re-download a package that has not
  changed and get one that has not changed.

  Every bound is checked before a byte is emitted, and a refusal names the
  member and both numbers rather than truncating anything.
  """
  @spec build(contents(), DateTime.t()) :: {:ok, binary()} | {:error, reason()}
  def build(contents, %DateTime{} = modified_at) do
    entries = [
      {@device_certificate, contents.device_certificate_pem},
      {@trust_anchor, contents.trust_anchor_pem},
      {@management_endpoint, contents.management_endpoint},
      {@configuration, contents.configuration_xml}
    ]

    with :ok <- check_members(entries) do
      archive =
        Enum.map_join(entries, "", fn {name, body} ->
          header(name, byte_size(body), DateTime.to_unix(modified_at)) <> pad(body)
        end) <> <<0::size(2 * @block * 8)>>

      {:ok, archive}
    end
  end

  @doc "A refusal in the words the administrator who composed the package needs."
  @spec describe(reason()) :: String.t()
  def describe({:member_too_large, name, size, bound}),
    do: "#{name} is #{size} bytes and the package bounds it at #{bound}"

  defp check_members(entries) do
    Enum.reduce_while(entries, :ok, fn {name, body}, :ok ->
      bound = Map.fetch!(@member_bounds, name)

      if byte_size(body) > bound do
        {:halt, {:error, {:member_too_large, name, byte_size(body), bound}}}
      else
        {:cont, :ok}
      end
    end)
  end

  # One ustar header. The checksum is computed over the header with its own
  # checksum field read as eight spaces, which is the definition the reader
  # applies on the way back in.
  defp header(name, size, modified_at) do
    without_checksum =
      field(name, 100) <>
        field(@mode, 8) <>
        field("0000000", 8) <>
        field("0000000", 8) <>
        octal(size, 12) <>
        octal(modified_at, 12) <>
        String.duplicate(" ", 8) <>
        "0" <>
        field("", 100) <>
        "ustar" <>
        <<0>> <>
        "00" <>
        field("", 32) <>
        field("", 32) <>
        field("", 8) <>
        field("", 8) <>
        field("", 155) <>
        field("", 12)

    checksum =
      without_checksum
      |> :binary.bin_to_list()
      |> Enum.sum()
      |> Integer.to_string(8)
      |> String.pad_leading(6, "0")

    <<before::binary-size(148), _spaces::binary-size(8), rest::binary>> = without_checksum
    before <> checksum <> <<0>> <> " " <> rest
  end

  defp field(value, width) do
    value <> <<0::size((width - byte_size(value)) * 8)>>
  end

  defp octal(value, width) do
    field(value |> Integer.to_string(8) |> String.pad_leading(width - 1, "0"), width)
  end

  defp pad(body) do
    case rem(byte_size(body), @block) do
      0 -> body
      remainder -> body <> <<0::size((@block - remainder) * 8)>>
    end
  end
end
