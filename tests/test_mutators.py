from waf_bypasser.prober import BlockMap
from waf_bypasser.mutators.encoder import EncoderMutator
from waf_bypasser.mutators.sql import SqlMutator
from waf_bypasser.mutators.ssrf import SsrfMutator

def test_encoder_mutator():
    bm = BlockMap()
    bm.blocked.add("'")
    bm.allowed.add("a")
    bm.allowed.add("b")

    mutator = EncoderMutator()
    mutations = mutator.mutate("a'b", bm)
    
    # URL encoded version of a'b is a%27b
    assert "a%27b" in mutations
    # Unicode version of a'b is a\u0027b
    assert "a\\u0027b" in mutations
    # Hex version of a'b is 0x612762
    assert "0x612762" in mutations

def test_sql_mutator_spaces():
    bm = BlockMap()
    bm.blocked.add(" ")
    bm.allowed.add("/")
    bm.allowed.add("*")

    mutator = SqlMutator()
    mutations = mutator.mutate("1 UNION SELECT", bm)
    
    # Space replaced by /**/
    assert "1/**/UNION/**/SELECT" in mutations

def test_sql_mutator_casing_and_operator():
    bm = BlockMap()
    bm.allowed.add("l")
    bm.allowed.add("i")
    bm.allowed.add("k")
    bm.allowed.add("e")

    mutator = SqlMutator()
    mutations = mutator.mutate("admin' OR 1=1", bm)
    
    # = replaced by LIKE
    assert any("LIKE" in m for m in mutations)
    # casing changes on OR
    assert any("Or" in m or "oR" in m or "OR" in m for m in mutations)

def test_ssrf_mutator():
    bm = BlockMap()
    bm.allowed.add("1")
    bm.allowed.add("2")
    bm.allowed.add("7")

    mutator = SsrfMutator()
    mutations = mutator.mutate("http://127.0.0.1/admin", bm)
    
    # Decimal representation
    assert any("2130706433" in m for m in mutations)
    # Hex representation
    assert any("0x7f000001" in m for m in mutations)
    # Alternate localhost domain
    assert any("local.gd" in m for m in mutations)
