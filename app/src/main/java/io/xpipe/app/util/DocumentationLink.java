package io.xpipe.app.util;

public enum DocumentationLink {
    INDEX(""),
    API("api"),
    TTY("troubleshoot/tty"),
    WINDOWS_SSH("troubleshoot/windows-ssh"),
    MACOS_SETUP("guide/installation#macos"),
    SSH_AGENT("troubleshoot/ssh-agent-socket"),
    DOUBLE_PROMPT("troubleshoot/two-step-connections"),
    LICENSE_ACTIVATION("troubleshoot/license-activation"),
    PRIVACY("legal/privacy"),
    EULA("legal/eula"),
    WEBTOP_UPDATE("guide/webtop#updating"),
    SYNC("guide/sync"),
    GETTING_STARTED("guide/getting-started"),
    DESKTOP_APPLICATIONS("guide/desktop-applications"),
    SERVICES("guide/services"),
    SCRIPTING("guide/scripting"),
    SCRIPTING_COMPATIBILITY("guide/scripting#shell-compatibility"),
    SCRIPTING_EDITING("guide/scripting#editing"),
    SCRIPTING_TYPES("guide/scripting#init-scripts"),
    SCRIPTING_DEPENDENCIES("guide/scripting#dependencies"),
    SCRIPTING_GROUPS("guide/scripting#groups"),
    KUBERNETES("guide/kubernetes"),
    DOCKER("guide/docker"),
    PROXMOX("guide/proxmox"),
    TAILSCALE("guide/tailscale"),
    TELEPORT("guide/teleport"),
    LXC("guide/lxc"),
    PODMAN("guide/podman"),
    KVM("guide/kvm"),
    VMWARE("guide/vmware"),
    VNC("guide/vnc"),
    SSH("guide/ssh"),
    PSSESSION("guide/pssession"),
    RDP("guide/rdp"),
    TUNNELS("guide/ssh-tunnels"),
    HYPERV("guide/hyperv"),
    SSH_MACS("guide/ssh#no-matching-mac-found"),
    KEEPASSXC("guide/password-manager#keepassxc"),
    PASSWORD_MANAGER("guide/password-manager");

    private final String page;

    DocumentationLink(String page) {
        this.page = page;
    }

    public void open() {
        Hyperlinks.open("https://docs.xpipe.io/" + page);
    }

    public String getLink() {
        return "https://docs.xpipe.io/" + page;
    }
}
