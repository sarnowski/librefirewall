defmodule Ctrld.ConfigurationTest do
  use ExUnit.Case, async: true

  alias Ctrld.Configuration

  describe "the template" do
    test "passes the checks this server makes" do
      assert Configuration.validate(Configuration.template()) == :ok
    end

    test "fits the package member's bound" do
      assert byte_size(Configuration.template()) <= Configuration.maximum_bytes()
    end

    test "carries every section the appliance's schema requires" do
      for section <- Configuration.required_sections() do
        assert String.contains?(Configuration.template(), "<#{section}")
      end
    end
  end

  describe "validation" do
    test "accepts a minimal document with all four sections" do
      document = """
      <?xml version="1.0" encoding="UTF-8"?>
      <configuration>
        <interfaces/>
        <neighbours/>
        <rules/>
        <management mac="52:54:00:12:34:52" address="10.0.2.15" prefix-length="24" enabled="true"/>
      </configuration>
      """

      assert Configuration.validate(document) == :ok
    end

    test "refuses a document over the package member's bound before parsing it" do
      oversize = String.duplicate("x", Configuration.maximum_bytes() + 1)
      assert {:error, {:too_large, size}} = Configuration.validate(oversize)
      assert size == Configuration.maximum_bytes() + 1
    end

    test "refuses bytes that are not well-formed XML" do
      assert Configuration.validate("<configuration>") == {:error, :not_well_formed}
      assert Configuration.validate("not xml at all") == {:error, :not_well_formed}
      assert Configuration.validate("<a></b>") == {:error, :not_well_formed}
      assert Configuration.validate("") == {:error, :not_well_formed}
    end

    test "refuses another root element" do
      assert Configuration.validate("<appliance/>") == {:error, {:wrong_root, "appliance"}}
    end

    test "refuses a document missing any required section" do
      for missing <- Configuration.required_sections() do
        sections =
          Configuration.required_sections()
          |> Enum.reject(&(&1 == missing))
          |> Enum.map_join("", &"<#{&1}/>")

        document = "<configuration>#{sections}</configuration>"
        assert Configuration.validate(document) == {:error, {:missing_section, missing}}
      end
    end

    test "refuses a repeated section" do
      document =
        "<configuration><interfaces/><interfaces/><neighbours/><rules/><management/></configuration>"

      assert Configuration.validate(document) == {:error, {:repeated_section, "interfaces"}}
    end

    test "refuses a document type declaration, so no entity can be expanded" do
      document = """
      <?xml version="1.0"?>
      <!DOCTYPE configuration [<!ENTITY a "aaaaaaaaaa">]>
      <configuration><interfaces/><neighbours/><rules/><management/></configuration>
      """

      assert Configuration.validate(document) == {:error, :declares_entities}
    end

    test "refuses an entity declaration whatever its case" do
      document = ~s(<!doctype x><configuration/>)
      assert Configuration.validate(document) == {:error, :declares_entities}
    end

    test "an expansion bomb never reaches the parser" do
      bomb = """
      <?xml version="1.0"?>
      <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
      ]>
      <configuration>&lol3;</configuration>
      """

      assert Configuration.validate(bomb) == {:error, :declares_entities}
    end

    test "arbitrary bytes never crash the validator" do
      for _ <- 1..200 do
        bytes = :crypto.strong_rand_bytes(:rand.uniform(512))

        assert Configuration.validate(bytes) in [:ok] or
                 match?({:error, _}, Configuration.validate(bytes))
      end
    end

    test "every refusal renders as a sentence" do
      reasons = [
        {:too_large, 99_999},
        :declares_entities,
        :not_well_formed,
        {:wrong_root, "appliance"},
        {:missing_section, "rules"},
        {:repeated_section, "rules"}
      ]

      for reason <- reasons do
        assert is_binary(Configuration.describe(reason))
        assert String.length(Configuration.describe(reason)) > 10
      end
    end
  end
end
