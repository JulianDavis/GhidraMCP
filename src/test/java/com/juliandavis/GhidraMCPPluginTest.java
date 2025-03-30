package com.juliandavis;

import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.program.model.lang.Processor;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import junit.framework.TestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assert.*;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

@Ignore("There is a bug here with imports or something, it's trying to resolve every possible import. I think it's how we're using Ghidra maybe. I fixed some of them but now its a logfj/Level class missing")
public class GhidraMCPPluginTest extends AbstractGhidraHeadlessIntegrationTest {
    private TestEnv env;
    private PluginTool tool;
    private Program program;
    private GhidraMCPPlugin plugin;

    @Before
    public void setUp() throws Exception {
        // Initialize test environment
        env = new TestEnv();
        tool = env.getTool();
        tool.addPlugin(NavigationHistoryPlugin.class.getName());
        tool.addPlugin(GhidraMCPPlugin.class.getName());
        
        // Get the plugin
        plugin = env.getPlugin(GhidraMCPPlugin.class);
        assertNotNull("GhidraMCPPlugin should be loaded", plugin);
        
        // Create a dummy program
        Language language = DefaultLanguageService.getLanguageService().getDefaultLanguage(Processor.findOrPossiblyCreateProcessor("x86:LE:32:default"));
        CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
        program = new ProgramDB("Test Program", language, compilerSpec, this);
        env.open(program);
    }

    @After
    public void tearDown() throws Exception {
        env.dispose();
    }

    /**
     * Basic test to ensure the server is started and responds to requests
     */
    @Test
    public void testServerStartup() throws Exception {
        // Give the server time to start
        Thread.sleep(1000);
        
        // Send a request to the programInfo endpoint
        URL url = new URL("http://localhost:8080/programInfo");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        // Check if the server responds
        assertEquals("Server should respond with 200 OK", 200, conn.getResponseCode());
        
        // Check if the response is not empty
        Scanner scanner = new Scanner(conn.getInputStream());
        StringBuilder response = new StringBuilder();
        while (scanner.hasNextLine()) {
            response.append(scanner.nextLine());
        }
        scanner.close();
        
        // The response should not be empty
        assertFalse("Response should not be empty", response.toString().isEmpty());
        
        // Response should contain success: true
        assertTrue("Response should indicate success", response.toString().contains("\"success\":true"));
    }
}
