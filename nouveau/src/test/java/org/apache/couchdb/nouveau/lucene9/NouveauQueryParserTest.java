//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.apache.couchdb.nouveau.lucene9;

import static org.assertj.core.api.Assertions.assertThat;

import java.text.NumberFormat;
import java.util.Map;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.DoublePoint;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.flexible.standard.StandardQueryParser;
import org.apache.lucene.queryparser.flexible.standard.config.PointsConfig;
import org.apache.lucene.search.PrefixQuery;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TermRangeQuery;
import org.apache.lucene.search.WildcardQuery;
import org.apache.lucene.util.BytesRef;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class NouveauQueryParserTest {

    private static final String DEFAULT_FIELD = "foo";

    private static StandardQueryParser qp;

    @BeforeAll
    public static void setup() {
        qp = new StandardQueryParser(new StandardAnalyzer());
        qp.setPointsConfigMap(Map.of("num", new PointsConfig(NumberFormat.getInstance(), Double.class)));
    }

    @Test
    public void testTermQuery() throws Exception {
        assertThat(qp.parse("foo:bar", DEFAULT_FIELD)).isEqualTo(new TermQuery(new Term("foo", "bar")));
    }

    @Test
    public void testPrefixQuery() throws Exception {
        assertThat(qp.parse("foo:bar*", DEFAULT_FIELD)).isEqualTo(new PrefixQuery(new Term("foo", "bar")));
    }

    @Test
    public void testWildcardQuery() throws Exception {
        assertThat(qp.parse("foo:ba*r", DEFAULT_FIELD)).isEqualTo(new WildcardQuery(new Term("foo", "ba*r")));
    }

    @Test
    public void testStringRangeQuery() throws Exception {
        assertThat(qp.parse("foo:[bar TO foo]", DEFAULT_FIELD))
                .isEqualTo(new TermRangeQuery("foo", new BytesRef("bar"), new BytesRef("foo"), true, true));
    }

    @Test
    public void testMixedRangeQuery() throws Exception {
        assertThat(qp.parse("foo:[12.0 TO foo]", DEFAULT_FIELD))
                .isEqualTo(new TermRangeQuery("foo", new BytesRef("12.0"), new BytesRef("foo"), true, true));
    }

    @Test
    public void testInferredPointQuery() throws Exception {
        assertThat(qp.parse("num:12", DEFAULT_FIELD)).isEqualTo(DoublePoint.newExactQuery("num", 12.0));
    }

    @Test
    public void testInferredPointRangeQuery() throws Exception {
        assertThat(qp.parse("num:[1 TO 12]", DEFAULT_FIELD))
                .isEqualTo(DoublePoint.newRangeQuery("num", new double[] {1}, new double[] {12}));
    }

    @Test
    public void testOpenLeftPointRangeQuery() throws Exception {
        assertThat(qp.parse("num:[* TO 100.0]", DEFAULT_FIELD))
                .isEqualTo(
                        DoublePoint.newRangeQuery("num", new double[] {Double.NEGATIVE_INFINITY}, new double[] {100}));
    }

    @Test
    public void testOpenRightPointRangeQuery() throws Exception {
        assertThat(qp.parse("num:[1.0 TO *]", DEFAULT_FIELD))
                .isEqualTo(DoublePoint.newRangeQuery("num", new double[] {1}, new double[] {Double.POSITIVE_INFINITY}));
    }
}
