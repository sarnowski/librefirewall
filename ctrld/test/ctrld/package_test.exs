defmodule Ctrld.PackageTest do
  @moduledoc """
  The package writer against the format's own rules.

  These tests are the mechanism that keeps this writer and the appliance's
  reader from drifting: `Ctrld.PackageContract` decodes what the writer
  produced by the contract's rules rather than by the writer's assumptions,
  and a change the writer makes that the contract does not admit fails here
  the moment it is made.
  """

  use ExUnit.Case, async: true

  alias Ctrld.{Package, PackageContract}

  @modified_at ~U[2026-08-04 12:00:00Z]

  defp contents(overrides \\ %{}) do
    Map.merge(
      %{
        device_certificate_pem:
          "-----BEGIN CERTIFICATE-----\ndevice\n-----END CERTIFICATE-----\n",
        trust_anchor_pem: "-----BEGIN CERTIFICATE-----\nanchor\n-----END CERTIFICATE-----\n",
        management_endpoint: "192.0.2.10:8443\n",
        configuration_xml: "<configuration/>\n"
      },
      overrides
    )
  end

  describe "the archive the writer produces" do
    setup do
      {:ok, archive} = Package.build(contents(), @modified_at)
      %{archive: archive}
    end

    test "decodes against every rule the contract states", %{archive: archive} do
      assert {:ok, members} = PackageContract.decode(archive)
      assert Map.keys(members) |> Enum.sort() == Enum.sort(PackageContract.names())
    end

    test "carries exactly the four members, with exactly the bodies given", %{archive: archive} do
      {:ok, members} = PackageContract.decode(archive)
      expected = contents()

      assert members["device-certificate.pem"] == expected.device_certificate_pem
      assert members["trust-anchor.pem"] == expected.trust_anchor_pem
      assert members["management-endpoint"] == expected.management_endpoint
      assert members["configuration.xml"] == expected.configuration_xml
    end

    test "is a whole number of 512-byte blocks and ends with two zero blocks", %{
      archive: archive
    } do
      assert rem(byte_size(archive), 512) == 0
      assert binary_part(archive, byte_size(archive) - 1024, 1024) == <<0::size(1024 * 8)>>
    end

    test "every header states ustar and version 00", %{archive: archive} do
      for header <- headers(archive) do
        assert binary_part(header, 257, 8) == "ustar" <> <<0>> <> "00"
      end
    end

    test "every member is a regular file", %{archive: archive} do
      for header <- headers(archive), do: assert(binary_part(header, 156, 1) == "0")
    end

    test "every name is exact, with no path and no prefix field", %{archive: archive} do
      names = Enum.map(headers(archive), &(&1 |> binary_part(0, 100) |> trim_nul()))

      assert Enum.sort(names) == Enum.sort(PackageContract.names())
      refute Enum.any?(names, &String.contains?(&1, "/"))

      for header <- headers(archive) do
        assert binary_part(header, 345, 155) == <<0::size(155 * 8)>>
      end
    end

    test "the link name field is empty on every header", %{archive: archive} do
      for header <- headers(archive) do
        assert binary_part(header, 157, 100) == <<0::size(100 * 8)>>
      end
    end

    test "every size field is octal and matches the bytes present", %{archive: archive} do
      expected = contents()

      sizes = %{
        "device-certificate.pem" => byte_size(expected.device_certificate_pem),
        "trust-anchor.pem" => byte_size(expected.trust_anchor_pem),
        "management-endpoint" => byte_size(expected.management_endpoint),
        "configuration.xml" => byte_size(expected.configuration_xml)
      }

      for header <- headers(archive) do
        name = header |> binary_part(0, 100) |> trim_nul()
        stated = header |> binary_part(124, 12) |> trim_nul() |> String.to_integer(8)
        assert stated == Map.fetch!(sizes, name)
      end
    end

    test "every header checksum verifies", %{archive: archive} do
      for header <- headers(archive) do
        <<before::binary-size(148), stated::binary-size(8), rest::binary>> = header

        computed =
          (before <> String.duplicate(" ", 8) <> rest) |> :binary.bin_to_list() |> Enum.sum()

        assert stated |> trim_nul() |> String.trim() |> String.to_integer(8) == computed
      end
    end

    test "no member carries a PAX or GNU extension type flag", %{archive: archive} do
      for header <- headers(archive) do
        refute binary_part(header, 156, 1) in ~w(x g L K V)
      end
    end

    test "the whole archive is inside the contract's bound", %{archive: archive} do
      assert byte_size(archive) <= PackageContract.archive_bound()
    end

    test "the same inputs produce the same bytes", %{archive: archive} do
      {:ok, again} = Package.build(contents(), @modified_at)
      assert again == archive
    end

    test "a different modification instant changes only the headers' time fields" do
      {:ok, first} = Package.build(contents(), @modified_at)
      {:ok, second} = Package.build(contents(), ~U[2027-01-01 00:00:00Z])
      refute first == second
      assert {:ok, members} = PackageContract.decode(second)
      assert map_size(members) == 4
    end
  end

  describe "bounds" do
    test "each member's bound is the contract's" do
      assert Package.member_bound("device-certificate.pem") == 16 * 1024
      assert Package.member_bound("trust-anchor.pem") == 16 * 1024
      assert Package.member_bound("management-endpoint") == 32
      assert Package.member_bound("configuration.xml") == 64 * 1024
      assert Package.archive_bound() == 128 * 1024
    end

    test "a member at its bound is accepted" do
      at_bound = String.duplicate("x", Package.member_bound("management-endpoint"))

      assert {:ok, archive} =
               Package.build(contents(%{management_endpoint: at_bound}), @modified_at)

      assert {:ok, members} = PackageContract.decode(archive)
      assert members["management-endpoint"] == at_bound
    end

    test "a member one byte over its bound is refused, naming both numbers" do
      over = String.duplicate("x", Package.member_bound("management-endpoint") + 1)

      assert {:error, {:member_too_large, "management-endpoint", 33, 32}} =
               Package.build(contents(%{management_endpoint: over}), @modified_at)
    end

    test "each member is bounded separately" do
      for {field, name} <- [
            {:device_certificate_pem, "device-certificate.pem"},
            {:trust_anchor_pem, "trust-anchor.pem"},
            {:management_endpoint, "management-endpoint"},
            {:configuration_xml, "configuration.xml"}
          ] do
        over = String.duplicate("x", Package.member_bound(name) + 1)

        assert {:error, {:member_too_large, ^name, _size, _bound}} =
                 Package.build(contents(%{field => over}), @modified_at)
      end
    end

    test "the largest archive the member bounds allow still fits the archive bound" do
      largest =
        Package.build(
          contents(%{
            device_certificate_pem:
              String.duplicate("x", Package.member_bound("device-certificate.pem")),
            trust_anchor_pem: String.duplicate("x", Package.member_bound("trust-anchor.pem")),
            management_endpoint:
              String.duplicate("x", Package.member_bound("management-endpoint")),
            configuration_xml: String.duplicate("x", Package.member_bound("configuration.xml"))
          }),
          @modified_at
        )

      assert {:ok, archive} = largest
      assert byte_size(archive) <= Package.archive_bound()
      assert {:ok, _members} = PackageContract.decode(archive)
    end

    test "every refusal renders as a sentence" do
      assert Package.describe({:member_too_large, "configuration.xml", 70_000, 65_536}) =~
               "configuration.xml"
    end
  end

  describe "the contract reader itself" do
    test "refuses an archive that is not a whole number of blocks" do
      {:ok, archive} = Package.build(contents(), @modified_at)
      assert {:error, {:not_a_whole_number_of_blocks, _}} = PackageContract.decode(archive <> "x")
    end

    test "refuses a member the contract does not name" do
      {:ok, archive} = Package.build(contents(), @modified_at)
      renamed = rename_first_member(archive, "unexpected.pem")
      assert {:error, {:unknown_member, "unexpected.pem"}} = PackageContract.decode(renamed)
    end

    test "refuses a header whose checksum does not verify" do
      {:ok, archive} = Package.build(contents(), @modified_at)
      # Change a byte the checksum covers without recomputing it.
      <<before::binary-size(100), _byte, rest::binary>> = archive
      assert {:error, {:checksum_mismatch, _, _}} = PackageContract.decode(before <> "9" <> rest)
    end

    test "refuses a type flag that is not a regular file" do
      {:ok, archive} = Package.build(contents(), @modified_at)
      tampered = rewrite_and_fix_checksum(archive, 156, "5")
      assert {:error, {:not_a_regular_file, "5"}} = PackageContract.decode(tampered)
    end

    test "refuses a magic that is not ustar" do
      {:ok, archive} = Package.build(contents(), @modified_at)
      tampered = rewrite_and_fix_checksum(archive, 257, "gnutar")
      assert {:error, {:not_ustar, _, _}} = PackageContract.decode(tampered)
    end

    test "refuses an archive missing a member" do
      {:ok, archive} = Package.build(contents(), @modified_at)
      # Drop the last member's header and body, keeping the end-of-archive marker.
      truncated =
        binary_part(archive, 0, byte_size(archive) - 1024 - 1024) <> <<0::size(1024 * 8)>>

      assert {:error, {:missing_members, _}} = PackageContract.decode(truncated)
    end
  end

  defp headers(archive) do
    archive
    |> chunks()
    |> Enum.reduce({[], 0}, fn block, {headers, skip} ->
      cond do
        skip > 0 -> {headers, skip - 1}
        block == <<0::size(512 * 8)>> -> {headers, 0}
        true -> {[block | headers], blocks_of_body(block)}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp blocks_of_body(header) do
    size = header |> binary_part(124, 12) |> trim_nul() |> String.to_integer(8)
    div(size + 511, 512)
  end

  defp chunks(<<>>), do: []
  defp chunks(<<block::binary-size(512), rest::binary>>), do: [block | chunks(rest)]

  defp trim_nul(field), do: field |> :binary.split(<<0>>) |> hd()

  defp rename_first_member(archive, name) do
    <<_old::binary-size(100), rest::binary>> = archive
    padded = name <> <<0::size((100 - byte_size(name)) * 8)>>
    fix_checksum(padded <> rest)
  end

  defp rewrite_and_fix_checksum(archive, offset, replacement) do
    size = byte_size(replacement)
    <<before::binary-size(^offset), _old::binary-size(^size), rest::binary>> = archive
    fix_checksum(before <> replacement <> rest)
  end

  defp fix_checksum(archive) do
    <<header::binary-size(512), rest::binary>> = archive
    <<before::binary-size(148), _own::binary-size(8), tail::binary>> = header

    checksum =
      (before <> String.duplicate(" ", 8) <> tail)
      |> :binary.bin_to_list()
      |> Enum.sum()
      |> Integer.to_string(8)
      |> String.pad_leading(6, "0")

    before <> checksum <> <<0>> <> " " <> tail <> rest
  end
end
