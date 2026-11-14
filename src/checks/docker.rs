use super::Ctx;
use crate::docker;
use crate::model::{Category, Finding, Status};
use crate::util;

const CAT: Category = Category::Docker;

pub fn check(_ctx: &Ctx) -> Vec<Finding> {
    let Some(containers) = docker::list() else {
        return Vec::new(); // no Docker, or no access to it
    };
    let mut out = Vec::new();
    if containers.is_empty() {
        out.push(Finding::new("docker.none", CAT, "Container").set(Status::Ok, "Es läuft kein Container."));
        return out;
    }

    // Ports open to the network
    let open: Vec<(String, String, String)> = containers
        .iter()
        .flat_map(|c| {
            c.open_ports().into_iter().map(move |p| {
                (
                    format!("{}/{} – Container „{}“", p.proto, p.host_port, c.name),
                    p.local_binding(),
                    c.compose_file.clone(),
                )
            })
        })
        .collect();
    let f = Finding::new("docker.ports", CAT, "Aus dem Netz erreichbare Container-Ports").why(
        "Docker schreibt eigene Firewall-Regeln. Ein mit „8080:80“ veröffentlichter Port ist aus dem ganzen Netz erreichbar – auch bei eingeschalteter ufw.",
    );
    out.push(if open.is_empty() {
        f.set(Status::Ok, "Kein Container-Port ist an alle Netze gebunden.")
    } else {
        let mut f = f.set(
            Status::Warn,
            format!("{} aus dem Netz erreichbar.", util::plural(open.len(), "Container-Port ist", "Container-Ports sind")),
        );
        for (what, binding, file) in &open {
            f = f.detail(what.clone());
            f = f.detail(format!("   ersetzen durch: {binding}{}", if file.is_empty() { String::new() } else { format!("   (in {file})") }));
        }
        f.fix(
            "In der Compose-Datei (bzw. bei „docker run -p“) 127.0.0.1 voranstellen, wenn der Dienst nur auf diesem Laptop gebraucht wird, und den Container neu erstellen.",
            &["docker compose up -d"],
        )
    });

    // Containers that can take over the host
    let powerful: Vec<String> = containers
        .iter()
        .filter(|c| c.privileged || c.docker_socket)
        .map(|c| {
            let mut why = Vec::new();
            if c.privileged {
                why.push("privilegiert");
            }
            if c.docker_socket {
                why.push("Zugriff auf docker.sock");
            }
            format!("{} – {}", c.name, why.join(", "))
        })
        .collect();
    let f = Finding::new("docker.power", CAT, "Container mit Zugriff auf das Wirtssystem").why(
        "Ein privilegierter Container oder einer mit eingehängtem docker.sock kann den ganzen Laptop übernehmen. Wird so ein Dienst gehackt, hilft die Container-Grenze nicht.",
    );
    out.push(if powerful.is_empty() {
        f.set(Status::Ok, "Kein Container ist privilegiert oder hat Zugriff auf den Docker-Socket.")
    } else {
        f.set(Status::Warn, format!("{} können das Wirtssystem übernehmen.", util::plural(powerful.len(), "Container kann", "Container")))
            .details(powerful)
            .fix("Nur einsetzen, wenn es wirklich nötig ist (z. B. Verwaltungswerkzeuge), und solche Container nie aus dem Netz erreichbar machen.", &[])
    });

    // Host network, added capabilities, root
    let host_net: Vec<String> = containers.iter().filter(|c| c.host_network).map(|c| c.name.clone()).collect();
    if !host_net.is_empty() {
        out.push(
            Finding::new("docker.hostnet", CAT, "Container im Netz des Laptops")
                .set(Status::Info, format!("{} das Netzwerk des Laptops direkt (network_mode: host).", util::plural(host_net.len(), "Container nutzt", "Container nutzen")))
                .details(host_net)
                .why("Solche Container öffnen ihre Ports direkt auf dem Laptop; die Portliste oben zeigt sie nicht als Docker-Freigabe."),
        );
    }
    let root: Vec<String> = containers.iter().filter(|c| c.runs_as_root()).map(|c| c.name.clone()).collect();
    let f = Finding::new("docker.root", CAT, "Container, die als root laufen")
        .why("Läuft der Dienst im Container als root, hat ein Angreifer nach einem Ausbruch aus dem Container sofort Root-Rechte auf dem Laptop.");
    out.push(if root.is_empty() {
        f.set(Status::Ok, format!("Alle {} Container laufen mit einem eingeschränkten Benutzer.", containers.len()))
    } else {
        f.set(Status::Info, format!("{} von {} Containern laufen als root.", root.len(), containers.len()))
            .details(root)
            .fix("Wo das Image es unterstützt, in der Compose-Datei einen Benutzer setzen.", &["user: \"1000:1000\""])
    });
    out
}
