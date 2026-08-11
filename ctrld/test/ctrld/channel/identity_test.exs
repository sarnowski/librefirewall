defmodule Ctrld.Channel.IdentityTest do
  @moduledoc """
  Who a peer certificate says the appliance is, and every way it says nothing.

  The certificates here are real ones, issued by the same code that issues the
  fleet's, because the whole point of this module is what it reads out of a
  structure this server produced — a hand-built tuple would prove agreement with
  itself.
  """

  use Ctrld.DataCase, async: true

  alias Ctrld.Channel.Identity
  alias Ctrld.PKI.{Certificate, KeyPair}

  setup do
    _authority = authority_fixture()
    :ok
  end

  describe "the device identifier a certificate names" do
    test "is the subject common name of a device certificate" do
      wanted = device_id()
      %{der: der} = device_certificate_fixture(wanted)

      assert Identity.device_id(der) == {:ok, wanted}
    end

    test "is read the same way whoever signed it" do
      # The identifier is a fact of the subject and not of the chain, so a
      # foreign certificate still names one. Whether that name is admitted is the
      # session's question and the transport already answered it.
      foreign = foreign_device_certificate_fixture()

      assert Identity.device_id(foreign.der) == {:ok, foreign.device_id}
    end
  end

  describe "the appliance a certificate names" do
    test "is the onboarded row whose device identifier it carries" do
      %{appliance: appliance} = onboarded_fixture()
      %{certificate_der: der, device_id: device_id} = appliance

      assert {:ok, ^device_id, found} = Identity.appliance(der)
      assert found.id == appliance.id
    end

    test "is refused where the identifier names no row" do
      wanted = device_id()
      %{der: der} = device_certificate_fixture(wanted)

      assert Identity.appliance(der) == {:error, {:unknown_appliance, wanted}}
    end
  end

  describe "refusing, by name" do
    test "no_peer_certificate" do
      assert Identity.device_id(nil) == {:error, :no_peer_certificate}
      assert Identity.appliance(nil) == {:error, :no_peer_certificate}
    end

    test "peer_certificate_unreadable, on bytes that are not a certificate" do
      assert Identity.device_id(<<>>) == {:error, :peer_certificate_unreadable}
      assert Identity.device_id("not a certificate") == {:error, :peer_certificate_unreadable}

      assert Identity.device_id(:crypto.strong_rand_bytes(512)) ==
               {:error, :peer_certificate_unreadable}
    end

    test "peer_certificate_unreadable, on a truncated certificate" do
      %{der: der} = device_certificate_fixture(device_id())
      truncated = binary_part(der, 0, div(byte_size(der), 2))

      assert Identity.device_id(truncated) == {:error, :peer_certificate_unreadable}
    end

    test "peer_common_name_not_a_device_id, on a subject of the wrong shape" do
      # An authority certificate: a real certificate of this server's, whose
      # subject is a name and not a device identifier.
      {:ok, {issued, _key}} = Certificate.create_authority("an authority", DateTime.utc_now())

      assert Identity.device_id(issued.der) == {:error, :peer_common_name_not_a_device_id}
    end

    test "peer_common_name_not_a_device_id, on hex of the wrong length" do
      short = String.duplicate("a", 31)
      long = String.duplicate("a", 33)

      for name <- [short, long] do
        {:ok, {authority, key}} = Certificate.create_authority("a", DateTime.utc_now())
        point = KeyPair.public_point(KeyPair.generate())

        {:ok, issued} =
          Certificate.issue_under(
            :device,
            name,
            point,
            authority.subject_common_name,
            key,
            DateTime.utc_now()
          )

        assert Identity.device_id(issued.der) == {:error, :peer_common_name_not_a_device_id}
      end
    end

    test "peer_common_name_not_a_device_id, on hex that is not lower case" do
      upper = String.duplicate("A", 32)
      {:ok, {authority, key}} = Certificate.create_authority("a", DateTime.utc_now())
      point = KeyPair.public_point(KeyPair.generate())

      {:ok, issued} =
        Certificate.issue_under(
          :device,
          upper,
          point,
          authority.subject_common_name,
          key,
          DateTime.utc_now()
        )

      assert Identity.device_id(issued.der) == {:error, :peer_common_name_not_a_device_id}
    end

    test "every refusal has words of its own" do
      refusals = [
        :no_peer_certificate,
        :peer_certificate_unreadable,
        :peer_subject_not_common_name,
        :peer_common_name_not_a_device_id,
        {:unknown_appliance, device_id()}
      ]

      described = Enum.map(refusals, &Identity.describe/1)

      assert Enum.all?(described, &is_binary/1)
      assert length(Enum.uniq(described)) == length(refusals)
    end

    test "a refusal never repeats the peer's own bytes" do
      # The identifier a stranger's certificate carried is the peer's to choose,
      # so what an operator reads says what was wrong and not what was sent.
      wanted = device_id()
      refute Identity.describe({:unknown_appliance, wanted}) =~ wanted
    end
  end
end
