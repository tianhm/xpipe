package io.xpipe.app.prefs;

import io.xpipe.app.comp.base.DescriptionButtonComp;
import io.xpipe.app.core.AppI18n;
import io.xpipe.app.core.AppLogs;
import io.xpipe.app.core.AppWindowHelper;
import io.xpipe.app.core.mode.OperationMode;
import io.xpipe.app.fxcomps.Comp;
import io.xpipe.app.fxcomps.CompStructure;
import io.xpipe.app.fxcomps.impl.VerticalComp;
import io.xpipe.app.issue.ErrorEvent;
import io.xpipe.app.issue.UserReportComp;
import io.xpipe.app.util.*;
import io.xpipe.core.impl.FileNames;
import io.xpipe.core.process.OsType;
import io.xpipe.core.store.ShellStore;
import io.xpipe.core.util.XPipeInstallation;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;

import java.util.List;

public class AboutComp extends Comp<CompStructure<?>> {

    private Region createDepsList() {
        var deps = new ThirdPartyDependencyListComp().createRegion();
        return deps;
    }

    private Comp<?> createActions() {
        return new OptionsBuilder()
                .addTitle("usefulActions")
                .addComp(
                        new DescriptionButtonComp("reportIssue", "reportIssueDescription", "mdal-bug_report", e -> {
                                    var event = ErrorEvent.fromMessage("User Report");
                                    if (AppLogs.get().isWriteToFile()) {
                                        event.attachment(AppLogs.get().getSessionLogsDirectory());
                                    }
                                    UserReportComp.show(event.build());
                                    e.consume();
                                })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp(
                                        "openCurrentLogFile",
                                        "openCurrentLogFileDescription",
                                        "mdmz-text_snippet",
                                        e -> {
                                            FileOpener.openInTextEditor(AppLogs.get()
                                                    .getSessionLogsDirectory()
                                                    .resolve("xpipe.log")
                                                    .toString());
                                            e.consume();
                                        })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp(
                                        "launchDebugMode", "launchDebugModeDescription", "mdmz-refresh", e -> {
                                            OperationMode.executeAfterShutdown(() -> {
                                                try (var sc = ShellStore.createLocal()
                                                        .control()
                                                        .start()) {
                                                    var script = FileNames.join(
                                                            XPipeInstallation.getCurrentInstallationBasePath()
                                                                    .toString(),
                                                            XPipeInstallation.getDaemonDebugScriptPath(sc.getOsType()));
                                                    if (sc.getOsType().equals(OsType.WINDOWS)) {
                                                        sc.executeSimpleCommand(ScriptHelper.createDetachCommand(
                                                                sc, "\"" + script + "\""));
                                                    } else {
                                                        TerminalHelper.open("XPipe Debug", "\"" + script + "\"");
                                                    }
                                                }
                                            });
                                            DesktopHelper.browsePath(
                                                    AppLogs.get().getSessionLogsDirectory());
                                            e.consume();
                                        })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp(
                                        "openInstallationDirectory",
                                        "openInstallationDirectoryDescription",
                                        "mdomz-snippet_folder",
                                        e -> {
                                            DesktopHelper.browsePath(
                                                    XPipeInstallation.getCurrentInstallationBasePath());
                                            e.consume();
                                        })
                                .grow(true, false),
                        null)
                .buildComp();
    }

    private Comp<?> createLinks() {
        return new OptionsBuilder()
                .addComp(
                        new DescriptionButtonComp(
                                        "securityPolicy", "securityPolicyDescription", "mdrmz-security", e -> {
                                            Hyperlinks.open(Hyperlinks.SECURITY);
                                            e.consume();
                                        })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp("privacy", "privacyDescription", "mdomz-privacy_tip", e -> {
                                    Hyperlinks.open(Hyperlinks.PRIVACY);
                                    e.consume();
                                })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp(
                                        "thirdParty", "thirdPartyDescription", "mdi2o-open-source-initiative", e -> {
                                            AppWindowHelper.sideWindow(
                                                            AppI18n.get("openSourceNotices"),
                                                            stage -> Comp.of(() -> createThirdPartyDeps()),
                                                            true,
                                                            null)
                                                    .show();
                                            e.consume();
                                        })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp("discord", "discordDescription", "mdi2d-discord", e -> {
                                    Hyperlinks.open(Hyperlinks.DISCORD);
                                    e.consume();
                                })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp("slack", "slackDescription", "mdi2s-slack", e -> {
                                    Hyperlinks.open(Hyperlinks.SLACK);
                                    e.consume();
                                })
                                .grow(true, false),
                        null)
                .addComp(
                        new DescriptionButtonComp("github", "githubDescription", "mdi2g-github", e -> {
                                    Hyperlinks.open(Hyperlinks.GITHUB);
                                    e.consume();
                                })
                                .grow(true, false),
                        null)
                .buildComp();
    }

    private Region createThirdPartyDeps() {
        var list = new ThirdPartyDependencyListComp().createRegion();
        list.getStyleClass().add("open-source-notices");
        var sp = new ScrollPane(list);
        sp.setFitToWidth(true);
        sp.setPrefWidth(600);
        sp.setPrefHeight(500);
        return sp;
    }

    @Override
    public CompStructure<?> createBase() {
        var props = new PropertiesComp().padding(new Insets(0, 0, 0, 15));
        var update = Comp.derive(new UpdateCheckComp(), u -> {
                    var sp = new StackPane(u);
                    sp.setAlignment(Pos.CENTER);
                    sp.setPadding(new Insets(10, 0, 10, 15));
                    return sp;
                })
                .grow(true, false);
        var box = new VerticalComp(List.of(props, update, createLinks(), createActions()))
                .apply(s -> s.get().setFillWidth(true))
                .apply(struc -> struc.get().setSpacing(15))
                .styleClass("information")
                .styleClass("about-tab")
                .apply(struc -> struc.get().setPrefWidth(800));
        return box.createStructure();
    }
}
