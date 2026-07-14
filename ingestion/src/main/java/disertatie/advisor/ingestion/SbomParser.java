package disertatie.advisor.ingestion;

import disertatie.contracts.model.Component;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class SbomParser {

    public List<Component> parse(Path bomFile) throws Exception {
        JsonParser parser = new JsonParser();
        Bom bom = parser.parse(bomFile.toFile());

        Map<String, DependencyDepths.Result> depths = DependencyDepths.compute(bom);

        List<Component> result = new ArrayList<>();
        if (bom.getComponents() == null) return result;

        for (org.cyclonedx.model.Component c : bom.getComponents()) {
            if (c.getPurl() == null) continue;

            DependencyDepths.Result info = depths.getOrDefault(
                    c.getBomRef(),
                    new DependencyDepths.Result(Integer.MAX_VALUE, false, "")
            );

            result.add(new Component(
                    c.getPurl(),
                    c.getGroup() != null ? c.getGroup() : "",
                    c.getName() != null ? c.getName() : "",
                    c.getVersion() != null ? c.getVersion() : "",
                    info.direct(),
                    info.depth(),
                    info.path()
            ));
        }

        return result;
    }
}
