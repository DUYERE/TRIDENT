package example.advanced;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [04] Intentionally vulnerable training material; lambda, generic and varargs overloads.
@RestController
@RequestMapping("/synthetic/advanced")
public final class LambdaGenericVarargsController {
    private final Connection connection;
    private final LambdaRepo lambdaRepo;
    private final LambdaAmbiguous lambdaAmbiguous;
    private final VarRepo varRepo;
    private final GenRepo genRepo;

    public LambdaGenericVarargsController(Connection connection, LambdaRepo lambdaRepo,
                                          LambdaAmbiguous lambdaAmbiguous, VarRepo varRepo, GenRepo genRepo) {
        this.connection = connection;
        this.lambdaRepo = lambdaRepo;
        this.lambdaAmbiguous = lambdaAmbiguous;
        this.varRepo = varRepo;
        this.genRepo = genRepo;
    }

    @GetMapping("/lambda")
    public void lambda(@RequestParam("q") String q) throws SQLException {
        String sql = lambdaRepo.find(x -> q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/lambda-ambiguous")
    public void lambdaAmbiguous(@RequestParam("q") String q) throws SQLException {
        // [05] fixture:ambiguous-lambda; both functional interfaces accept the lambda.
        String sql = lambdaAmbiguous.find(x -> q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/varargs")
    public void varargs(@RequestParam("q") String q) throws SQLException {
        String sql = varRepo.join("p", q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/varargs-ambiguous")
    public void varargsAmbiguous(@RequestParam("q") String q) throws SQLException {
        // [06] fixture:ambiguous-varargs; both varargs overloads accept zero varargs.
        String sql = varRepo.join(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/generic")
    public void generic(@RequestParam("q") String q) throws SQLException {
        String sql = genRepo.find(genRepo.pass(q));
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/generic-direct")
    public void genericDirect(@RequestParam("q") String q) throws SQLException {
        String sql = genRepo.pass(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
